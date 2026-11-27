// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 *
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#include <assert.h>
#include <drivers/mailbox.h>
#include <drivers/mailbox_controller.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <stdlib.h>
#include <string.h>
#include <tee/cache.h>
#include "drivers/versal_mbox.h"

#if defined(PLATFORM_FLAVOR_net)
#define IPI_REG_BASEADDR		0xEB300000
#define IPI_BUFFER_BASEADDR		0xEB3F0000
#else
#define IPI_REG_BASEADDR		0xFF300000
#define IPI_BUFFER_BASEADDR		0xFF3F0000
#endif

#define IPI_SIZE			0x10000

#define IPI_TRIG_OFFSET			0x00
#define IPI_OBR_OFFSET			0x04
#define IPI_ISR_OFFSET			0x10
#define IPI_IMR_OFFSET			0x14
#define IPI_IER_OFFSET			0x18
#define IPI_IDR_OFFSET			0x1C

#define IPI_PMC_TRIG_BIT		BIT(1)
#define IPI0_TRIG_BIT			BIT(2)
#define IPI1_TRIG_BIT			BIT(3)
#define IPI2_TRIG_BIT			BIT(4)
#define IPI3_TRIG_BIT			BIT(5)
#define IPI4_TRIG_BIT			BIT(6)
#define IPI5_TRIG_BIT			BIT(7)

/* Interrupt Config Registers */
#define IPI_PMC_REG_BASE		(IPI_REG_BASEADDR + 0x20000)
#define IPI0_REG_BASE			(IPI_REG_BASEADDR + 0x30000)
#define IPI1_REG_BASE			(IPI_REG_BASEADDR + 0x40000)
#define IPI2_REG_BASE			(IPI_REG_BASEADDR + 0x50000)
#define IPI3_REG_BASE			(IPI_REG_BASEADDR + 0x60000)
#define IPI4_REG_BASE			(IPI_REG_BASEADDR + 0x70000)
#define IPI5_REG_BASE			(IPI_REG_BASEADDR + 0x80000)

/* Buffers */
#define IPI_BUFFER_PMC_BASE		(IPI_BUFFER_BASEADDR + 0x200)
#define IPI_BUFFER_APU_ID_0_BASE	(IPI_BUFFER_BASEADDR + 0x400)
#define IPI_BUFFER_APU_ID_1_BASE	(IPI_BUFFER_BASEADDR + 0x600)
#define IPI_BUFFER_APU_ID_2_BASE	(IPI_BUFFER_BASEADDR + 0x800)
#define IPI_BUFFER_APU_ID_3_BASE	(IPI_BUFFER_BASEADDR + 0xA00)
#define IPI_BUFFER_APU_ID_4_BASE	(IPI_BUFFER_BASEADDR + 0xC00)
#define IPI_BUFFER_APU_ID_5_BASE	(IPI_BUFFER_BASEADDR + 0xE00)
#define IPI_BUFFER_TARGET_PMC_OFFSET	0x40
#define IPI_BUFFER_TARGET_ID_0_OFFSET	0x80
#define IPI_BUFFER_TARGET_ID_1_OFFSET	0xC0
#define IPI_BUFFER_TARGET_ID_2_OFFSET	0x100
#define IPI_BUFFER_TARGET_ID_3_OFFSET	0x140
#define IPI_BUFFER_TARGET_ID_4_OFFSET	0x180
#define IPI_BUFFER_TARGET_ID_5_OFFSET	0x1C0

#define IPI_BUFFER_REQ_OFFSET		0x0
#define IPI_BUFFER_RESP_OFFSET		0x20

static const struct versal_ipi_cfg {
	uint32_t ipi_bit_mask;
	uint32_t ipi_reg_base;
	uint32_t ipi_buf_base;
	uint32_t ipi_remote_offset;
} versal_ipi_cfgs[] = {
	/* PMC IPI */
	[VERSAL_IPI_ID_PMC] = {
		.ipi_bit_mask = IPI_PMC_TRIG_BIT,
		.ipi_reg_base = IPI_PMC_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_PMC_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_PMC_OFFSET,
	},

	/* IPI0 IPI */
	[VERSAL_IPI_ID_0] = {
		.ipi_bit_mask = IPI0_TRIG_BIT,
		.ipi_reg_base = IPI0_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_0_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_0_OFFSET,
	},

	/* IPI1 IPI */
	[VERSAL_IPI_ID_1] = {
		.ipi_bit_mask = IPI1_TRIG_BIT,
		.ipi_reg_base = IPI1_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_1_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_1_OFFSET,
	},

	/* IPI2 IPI */
	[VERSAL_IPI_ID_2] = {
		.ipi_bit_mask = IPI2_TRIG_BIT,
		.ipi_reg_base = IPI2_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_2_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_2_OFFSET,
	},

	/* IPI3 IPI */
	[VERSAL_IPI_ID_3] = {
		.ipi_bit_mask = IPI3_TRIG_BIT,
		.ipi_reg_base = IPI3_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_3_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_3_OFFSET,
	},

	/* IPI4 IPI */
	[VERSAL_IPI_ID_4] = {
		.ipi_bit_mask = IPI4_TRIG_BIT,
		.ipi_reg_base = IPI4_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_4_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_4_OFFSET,
	},

	/* IPI5 IPI */
	[VERSAL_IPI_ID_5] = {
		.ipi_bit_mask = IPI5_TRIG_BIT,
		.ipi_reg_base = IPI5_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_5_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_5_OFFSET,
	},
};

#define IPI_REG_BASE(idx) (versal_ipi_cfgs[idx].ipi_reg_base)
#define IPI_BIT_MASK(idx) (versal_ipi_cfgs[idx].ipi_bit_mask)
#define IPI_BUFFER_BASE(idx) (versal_ipi_cfgs[idx].ipi_buf_base)
#define IPI_REMOTE_OFFSET(idx) (versal_ipi_cfgs[idx].ipi_remote_offset)

/*
 * struct versal_chan - Versal IPI channel
 * @chan: Mailbox framework channel handle
 * @lcl: Local IPI ID
 * @rmt: Remote IPI ID
 * @lock: Exclusive access to the IPI shared buffer
 * @regs: IPI registers base address
 * @rsp: IPI response buffer
 * @req: IPI request buffer
 */
struct versal_chan {
	struct mbox_chan chan;
	uint32_t lcl;
	uint32_t rmt;
	struct mutex lock;
	vaddr_t regs;
	void *rsp;
	void *req;
};

static struct mbox_controller *versal_controller;

static TEE_Result versal_mbox_write_req(struct versal_chan *ipi,
					struct versal_ipi_cmd *cmd)
{
	size_t i = 0;

	assert(ipi);
	assert(cmd);

	for (i = 0; i < VERSAL_MAX_IPI_BUF; i++) {
		if (!cmd->ibuf[i].mem.buf)
			continue;

		if (!IS_ALIGNED((uintptr_t)cmd->ibuf[i].mem.buf,
				CACHELINE_LEN)) {
			EMSG("address not aligned: buffer %zu - %p", i,
			     cmd->ibuf[i].mem.buf);
			return TEE_ERROR_GENERIC;
		}

		if (!IS_ALIGNED(cmd->ibuf[i].mem.alloc_len, CACHELINE_LEN)) {
			EMSG("length not aligned: buffer %zu - %zu",
			     i, cmd->ibuf[i].mem.alloc_len);
			return TEE_ERROR_GENERIC;
		}

		cache_operation(TEE_CACHEFLUSH, cmd->ibuf[i].mem.buf,
				cmd->ibuf[i].mem.alloc_len);
	}

	memcpy(ipi->req, cmd->data, sizeof(cmd->data));

	/* Cache operation on the IPI buffer is safe */
	cache_operation(TEE_CACHEFLUSH, ipi->req, sizeof(cmd->data));

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_read_rsp(struct versal_chan *ipi,
				       struct versal_ipi_cmd *cmd,
				       struct versal_ipi_cmd *rsp,
				       uint32_t *status)
{
	size_t i = 0;

	assert(ipi);
	assert(cmd);

	/* Cache operation on the IPI buffer is safe */
	cache_operation(TEE_CACHEINVALIDATE, ipi->rsp, sizeof(rsp->data));

	*status = *(uint32_t *)ipi->rsp;

	if (*status)
		return TEE_ERROR_GENERIC;

	if (rsp)
		memcpy(rsp->data, ipi->rsp, sizeof(rsp->data));

	for (i = 0; i < VERSAL_MAX_IPI_BUF; i++) {
		if (!cmd->ibuf[i].mem.buf)
			continue;

		if (!IS_ALIGNED((uintptr_t)cmd->ibuf[i].mem.buf,
				CACHELINE_LEN)) {
			EMSG("address not aligned: buffer %zu - %p",
			     i, cmd->ibuf[i].mem.buf);
			return TEE_ERROR_GENERIC;
		}

		if (!IS_ALIGNED(cmd->ibuf[i].mem.alloc_len, CACHELINE_LEN)) {
			EMSG("length not aligned: buffer %zu - %zu",
			     i, cmd->ibuf[i].mem.alloc_len);
			return TEE_ERROR_GENERIC;
		}

		cache_operation(TEE_CACHEINVALIDATE,
				cmd->ibuf[i].mem.buf,
				cmd->ibuf[i].mem.alloc_len);
	}

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_request_channel(struct mbox_controller *ctrl __unused,
					      const uint32_t *args,
					      size_t args_count,
					      struct mbox_chan **chan)
{
	struct versal_chan *ipi = NULL;
	uint32_t local = 0;
	uint32_t remote = 0;

	if (args_count != 2)
		return TEE_ERROR_BAD_PARAMETERS;

	local = args[0];
	remote = args[1];
	if (local < VERSAL_IPI_ID_PMC || local > VERSAL_IPI_ID_5 ||
	    remote < VERSAL_IPI_ID_PMC || remote > VERSAL_IPI_ID_5)
		return TEE_ERROR_BAD_PARAMETERS;

	ipi = calloc(1, sizeof(*ipi));
	if (!ipi)
		return TEE_ERROR_OUT_OF_MEMORY;

	ipi->regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						  IPI_REG_BASE(local),
						  IPI_SIZE);

	ipi->req = core_mmu_add_mapping(MEM_AREA_IO_SEC,
					IPI_BUFFER_BASE(local) +
					IPI_REMOTE_OFFSET(remote) +
					IPI_BUFFER_REQ_OFFSET,
					sizeof(struct versal_ipi_cmd));

	ipi->rsp = core_mmu_add_mapping(MEM_AREA_IO_SEC,
					IPI_BUFFER_BASE(local) +
					IPI_REMOTE_OFFSET(remote) +
					IPI_BUFFER_RESP_OFFSET,
					sizeof(struct versal_ipi_cmd));

	ipi->lcl = local;
	ipi->rmt = remote;

	if (!ipi->regs || !ipi->req || !ipi->rsp)
		panic();

	mutex_init(&ipi->lock);

	io_write32(ipi->regs + IPI_IDR_OFFSET, IPI_BIT_MASK(remote));
	io_write32(ipi->regs + IPI_ISR_OFFSET, IPI_BIT_MASK(remote));

	*chan = &ipi->chan;

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_send_sync(const struct mbox_chan *chan,
					void *data)
{
	struct versal_chan *ipi = container_of(chan, struct versal_chan, chan);
	const struct versal_mbox_req *req = data;
	struct versal_ipi_cmd *cmd = req->cmd;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t remote_status = 0;

	mutex_lock(&ipi->lock);

	ret = versal_mbox_write_req(ipi, cmd);
	if (ret) {
		EMSG("Can't write the request command");
		goto out;
	}

	/* Trigger interrupt to remote */
	io_write32(ipi->regs + IPI_TRIG_OFFSET, IPI_BIT_MASK(ipi->rmt));

	/* Wait for remote to acknowledge the interrupt */
	if (IO_READ32_POLL_TIMEOUT(ipi->regs + IPI_OBR_OFFSET, remote_status,
				   !(remote_status & IPI_BIT_MASK(ipi->rmt)), 1,
				   CFG_VERSAL_MBOX_TIMEOUT)) {
		EMSG("Timeout waiting for remote response");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	ret = versal_mbox_read_rsp(ipi, cmd, req->rsp, &remote_status);
	if (ret)
		EMSG("Can't read the remote response");

	if (remote_status) {
		if (req->err)
			*req->err = remote_status;

		ret = TEE_ERROR_GENERIC;
	}
out:
	mutex_unlock(&ipi->lock);

	return ret;
}

static void versal_mbox_free_channel(struct mbox_chan *chan)
{
	struct versal_chan *ipi = container_of(chan, struct versal_chan, chan);

	io_write32(ipi->regs + IPI_IDR_OFFSET, IPI_BIT_MASK(ipi->rmt));
	free(ipi);
}

static const struct mbox_controller_ops versal_mbox_ops = {
	.request_channel = versal_mbox_request_channel,
	.free_channel = versal_mbox_free_channel,
	.send_sync = versal_mbox_send_sync,
};

static const struct mbox_controller_desc versal_mbox_desc = {
	.ops = &versal_mbox_ops,
};

TEE_Result versal_ipi_get_controller(struct mbox_controller **ctrl)
{
	TEE_Result res = TEE_SUCCESS;

	if (!versal_controller) {
		res = mbox_controller_register(&versal_controller,
					       &versal_mbox_desc);
		if (res)
			return res;
	}

	*ctrl = versal_controller;

	return TEE_SUCCESS;
}
