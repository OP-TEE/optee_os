// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <initcall.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <tee/cache.h>
#include "drivers/versal_mbox.h"

#define PM_SIP_SVC	0xc2000000

/* ipi targets */
#define IPI_ID_PMC	1
#define IPI_ID_0	2
#define IPI_ID_RPU0	3
#define IPI_ID_RPU1	4
#define IPI_ID_3	5
#define IPI_ID_4	6
#define IPI_ID_5	7

/* buffers */
#define IPI_BUFFER_BASEADDR		0xFF3F0000
#define IPI_BUFFER_APU_ID_0_BASE	(IPI_BUFFER_BASEADDR + 0x400)
#define IPI_BUFFER_APU_ID_3_BASE	(IPI_BUFFER_BASEADDR + 0xA00)
#define IPI_BUFFER_APU_ID_4_BASE	(IPI_BUFFER_BASEADDR + 0xC00)
#define IPI_BUFFER_APU_ID_5_BASE	(IPI_BUFFER_BASEADDR + 0xE00)
#define IPI_BUFFER_PMC_BASE		(IPI_BUFFER_BASEADDR + 0x200)
#define IPI_BUFFER_TARGET_APU_OFFSET	0x80
#define IPI_BUFFER_TARGET_PMC_OFFSET	0x40
#define IPI_BUFFER_REQ_OFFSET		0x0
#define IPI_BUFFER_RESP_OFFSET		0x20

#define IPI_BUFFER_LOCAL_OFFSET		IPI_BUFFER_TARGET_APU_OFFSET
#define IPI_BUFFER_REMOTE_OFFSET	IPI_BUFFER_TARGET_PMC_OFFSET

#define IPI_BLOCK		1
#define IPI_NON_BLOCK		0

/* mailbox api */
enum ipi_api_id {
	IPI_MAILBOX_OPEN = 0x1000,
	IPI_MAILBOX_RELEASE,
	IPI_MAILBOX_STATUS_ENQUIRY,
	IPI_MAILBOX_NOTIFY,
	IPI_MAILBOX_ACK,
	IPI_MAILBOX_ENABLE_IRQ,
	IPI_MAILBOX_DISABLE_IRQ
};

static struct versal_ipi {
	uint32_t lcl;
	const uint32_t rmt;
	paddr_t buf;
	/* Exclusive access to the IPI shared buffer */
	struct mutex lock;
	void *rsp;
	void *req;
} ipi = {
	.buf = IPI_BUFFER_APU_ID_3_BASE,
	.rmt = IPI_ID_PMC,
	.lcl = IPI_ID_3,
};

static TEE_Result mbox_call(enum ipi_api_id id, uint32_t blocking_call)
{
	struct thread_smc_args args = {
		.a0 = PM_SIP_SVC | id,
		.a1 = reg_pair_to_64(0, ipi.lcl),
		.a2 = reg_pair_to_64(0, ipi.rmt),
		.a3 = reg_pair_to_64(0, blocking_call),
	};

	thread_smccc(&args);

	if (IS_ENABLED(CFG_VERSAL_TRACE_PLM))
		mdelay(1000);

	if (args.a0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_write_req(struct ipi_cmd *cmd)
{
	size_t i = 0;

	for (i = 0; i < MAX_IPI_BUF; i++) {
		if (!cmd->ibuf[i].p)
			continue;

		if (!IS_ALIGNED((uintptr_t)cmd->ibuf[i].p, CACHELINE_LEN))
			return TEE_ERROR_GENERIC;

		if (!IS_ALIGNED(cmd->ibuf[i].len, CACHELINE_LEN))
			return TEE_ERROR_GENERIC;

		cache_operation(TEE_CACHEFLUSH,
				cmd->ibuf[i].p, cmd->ibuf[i].len);
	}

	memcpy(ipi.req, cmd->data, sizeof(cmd->data));
	/* cache operation on the IPI buffer is safe */
	cache_operation(TEE_CACHEFLUSH, ipi.req, sizeof(cmd->data));

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_read_rsp(struct ipi_cmd *cmd, struct ipi_cmd *rsp,
				       uint32_t *status)
{
	size_t i = 0;

	/* cache operation on the IPI buffer is safe */
	cache_operation(TEE_CACHEINVALIDATE, ipi.rsp, sizeof(rsp->data));

	*status = *(uint32_t *)ipi.rsp;

	if (rsp)
		memcpy(rsp->data, ipi.rsp, sizeof(rsp->data));

	if (*status)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < MAX_IPI_BUF; i++) {
		if (!cmd->ibuf[i].p)
			continue;

		if (!IS_ALIGNED((uintptr_t)cmd->ibuf[i].p, CACHELINE_LEN))
			return TEE_ERROR_GENERIC;

		if (!IS_ALIGNED(cmd->ibuf[i].len, CACHELINE_LEN))
			return TEE_ERROR_GENERIC;

		cache_operation(TEE_CACHEINVALIDATE,
				cmd->ibuf[i].p, cmd->ibuf[i].len);
	}

	return TEE_SUCCESS;
}

TEE_Result versal_mbox_notify(struct ipi_cmd *cmd, struct ipi_cmd *rsp)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t remote_status = 0;

	mutex_lock(&ipi.lock);

	ret = versal_mbox_write_req(cmd);
	if (ret) {
		EMSG("Can't write the request command");
		goto out;
	}

	ret = mbox_call(IPI_MAILBOX_NOTIFY, IPI_BLOCK);
	if (ret) {
		EMSG("IPI error");
		goto out;
	}

	ret = versal_mbox_read_rsp(cmd, rsp, &remote_status);
	if (ret) {
		EMSG("Can't read the remote response");
		goto out;
	}

	if (remote_status) {
		/* Check xplmi_status.h in the PLM code (hundreds of types) */
		EMSG("PLM (err=0x%x)", remote_status >> 16);
		ret = TEE_ERROR_GENERIC;
	}
out:
	mutex_unlock(&ipi.lock);

	return ret;
}

static TEE_Result versal_mbox_init(void)
{
	switch (CFG_VERSAL_MBOX_IPI_ID) {
	case 0:
		ipi.buf = IPI_BUFFER_APU_ID_0_BASE;
		ipi.lcl = IPI_ID_0;
		break;
	case 3:
		break;
	case 4:
		ipi.buf = IPI_BUFFER_APU_ID_4_BASE;
		ipi.lcl = IPI_ID_4;
		break;
	case 5:
		ipi.buf = IPI_BUFFER_APU_ID_5_BASE;
		ipi.lcl = IPI_ID_5;
		break;
	default:
		EMSG("Invalid IPI requested");
		return TEE_ERROR_GENERIC;
	}

	ipi.req = core_mmu_add_mapping(MEM_AREA_RAM_SEC,
				       ipi.buf + IPI_BUFFER_REMOTE_OFFSET +
				       IPI_BUFFER_REQ_OFFSET,
				       sizeof(struct ipi_cmd));

	ipi.rsp = core_mmu_add_mapping(MEM_AREA_RAM_SEC,
				       ipi.buf + IPI_BUFFER_REMOTE_OFFSET +
				       IPI_BUFFER_RESP_OFFSET,
				       sizeof(struct ipi_cmd));
	if (!ipi.req || !ipi.rsp)
		panic();

	mutex_init(&ipi.lock);

	return mbox_call(IPI_MAILBOX_OPEN, IPI_BLOCK);
}
early_init(versal_mbox_init);
