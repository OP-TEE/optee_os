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

/* IPI targets */
#define IPI_ID_PMC	1
#define IPI_ID_0	2
#define IPI_ID_RPU0	3
#define IPI_ID_RPU1	4
#define IPI_ID_3	5
#define IPI_ID_4	6
#define IPI_ID_5	7

/* Buffers */
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

/* Mailbox api */
enum versal_ipi_api_id {
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

static const char *const nvm_id[] = {
	[0] = "API_FEATURES",
	[1] = "BBRAM_WRITE_AES_KEY",
	[2] = "BBRAM_ZEROIZE",
	[3] = "BBRAM_WRITE_USER_DATA",
	[4] = "BBRAM_READ_USER_DATA",
	[5] = "BBRAM_LOCK_WRITE_USER_DATA",
	[6] = "EFUSE_WRITE",
	[7] = "EFUSE_WRITE_PUF",
	[8] = "EFUSE_PUF_USER_FUSE_WRITE",
	[9] = "EFUSE_READ_IV",
	[10] = "EFUSE_READ_REVOCATION_ID",
	[11] = "EFUSE_READ_OFFCHIP_REVOCATION_ID",
	[12] = "EFUSE_READ_USER_FUSES",
	[13] = "EFUSE_READ_MISC_CTRL",
	[14] = "EFUSE_READ_SEC_CTRL",
	[15] = "EFUSE_READ_SEC_MISC1",
	[16] = "EFUSE_READ_BOOT_ENV_CTRL",
	[17] = "EFUSE_READ_PUF_SEC_CTRL",
	[18] = "EFUSE_READ_PPK_HASH",
	[19] = "EFUSE_READ_DEC_EFUSE_ONLY",
	[20] = "EFUSE_READ_DNA",
	[21] = "EFUSE_READ_PUF_USER_FUSES",
	[22] = "EFUSE_READ_PUF",
	[23] = "EFUSE_INVALID",
};

static const char *const crypto_id[] = {
	[0] = "FEATURES",
	[1] = "RSA_SIGN_VERIFY",
	[2] = "RSA_PUBLIC_ENCRYPT",
	[3] = "RSA_PRIVATE_DECRYPT",
	[4] = "RSA_KAT",
	[32] = "SHA3_UPDATE",
	[33] = "SHA3_KAT",
	[64] = "ELLIPTIC_GENERATE_PUBLIC_KEY",
	[65] = "ELLIPTIC_GENERATE_SIGN",
	[66] = "ELLIPTIC_VALIDATE_PUBLIC_KEY",
	[67] = "ELLIPTIC_VERIFY_SIGN",
	[68] = "ELLIPTIC_KAT",
	[96] = "AES_INIT",
	[97] = "AES_OP_INIT",
	[98] = "AES_UPDATE_AAD",
	[99] = "AES_ENCRYPT_UPDATE",
	[100] = "AES_ENCRYPT_FINAL",
	[101] = "AES_DECRYPT_UPDATE",
	[102] = "AES_DECRYPT_FINAL",
	[103] = "AES_KEY_ZERO",
	[104] = "AES_WRITE_KEY",
	[105] = "AES_LOCK_USER_KEY",
	[106] = "AES_KEK_DECRYPT",
	[107] = "AES_SET_DPA_CM",
	[108] = "AES_DECRYPT_KAT",
	[109] = "AES_DECRYPT_CM_KAT",
	[110] = "MAX",
};

static const char *const puf_id[] = {
	[0] = "PUF_API_FEATURES",
	[1] = "PUF_REGISTRATION",
	[2] = "PUF_REGENERATION",
	[3] = "PUF_CLEAR_PUF_ID",
};

static const char *const module[] = {
	[5] = "CRYPTO",
	[7] = "FPGA",
	[11] = "NVM",
	[12] = "PUF",
};

static const char *const fpga_id[] = {
	[1] = "LOAD",
};

static void versal_mbox_call_trace(uint32_t call)
{
	uint32_t mid = call >>  8 & 0xff;
	uint32_t api = call & 0xff;
	const char *val = NULL;

	switch (mid) {
	case 5:
		if (api < ARRAY_SIZE(crypto_id))
			val = crypto_id[api];

		break;
	case 7:
		if (api < ARRAY_SIZE(fpga_id))
			val = fpga_id[api];

		break;
	case 11:
		if (api < ARRAY_SIZE(nvm_id))
			val = nvm_id[api];

		break;
	case 12:
		if (api < ARRAY_SIZE(puf_id))
			val = puf_id[api];

		break;
	default:
		break;
	}

	IMSG("--- mbox: service: %s\t call: %s", module[mid],
	     val ? val : "Invalid");
};

static TEE_Result mbox_call(enum versal_ipi_api_id id, uint32_t blocking_call)
{
	struct thread_smc_args args = {
		.a0 = PM_SIP_SVC | id,
		.a1 = reg_pair_to_64(0, ipi.lcl),
		.a2 = reg_pair_to_64(0, ipi.rmt),
		.a3 = reg_pair_to_64(0, blocking_call),
	};

	thread_smccc(&args);

	/* Give the PLM time to access the console */
	if (IS_ENABLED(CFG_VERSAL_TRACE_PLM))
		mdelay(500);

	if (args.a0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_write_req(struct versal_ipi_cmd *cmd)
{
	size_t i = 0;

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

	memcpy(ipi.req, cmd->data, sizeof(cmd->data));

	/* Cache operation on the IPI buffer is safe */
	cache_operation(TEE_CACHEFLUSH, ipi.req, sizeof(cmd->data));

	return TEE_SUCCESS;
}

static TEE_Result versal_mbox_read_rsp(struct versal_ipi_cmd *cmd,
				       struct versal_ipi_cmd *rsp,
				       uint32_t *status)
{
	size_t i = 0;

	/* Cache operation on the IPI buffer is safe */
	cache_operation(TEE_CACHEINVALIDATE, ipi.rsp, sizeof(rsp->data));

	*status = *(uint32_t *)ipi.rsp;

	if (*status)
		return TEE_ERROR_GENERIC;

	if (rsp)
		memcpy(rsp->data, ipi.rsp, sizeof(rsp->data));

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

TEE_Result versal_mbox_alloc(size_t len, const void *init,
			     struct versal_mbox_mem *mem)
{
	mem->buf = memalign(CACHELINE_LEN, ROUNDUP(len, CACHELINE_LEN));
	if (!mem->buf)
		panic();

	memset(mem->buf, 0, ROUNDUP(len, CACHELINE_LEN));

	if (init)
		memcpy(mem->buf, init, len);

	mem->alloc_len = ROUNDUP(len, CACHELINE_LEN);
	mem->len = len;

	return TEE_SUCCESS;
}

TEE_Result versal_mbox_notify(struct versal_ipi_cmd *cmd,
			      struct versal_ipi_cmd *rsp, uint32_t *err)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t remote_status = 0;

	mutex_lock(&ipi.lock);

	ret = versal_mbox_write_req(cmd);
	if (ret) {
		EMSG("Can't write the request command");
		goto out;
	}

	if (IS_ENABLED(CFG_VERSAL_TRACE_MBOX))
		versal_mbox_call_trace(cmd->data[0]);

	ret = mbox_call(IPI_MAILBOX_NOTIFY, IPI_BLOCK);
	if (ret) {
		EMSG("IPI error");
		goto out;
	}

	ret = versal_mbox_read_rsp(cmd, rsp, &remote_status);
	if (ret)
		EMSG("Can't read the remote response");

	if (remote_status) {
		if (err)
			*err = remote_status;
		/*
		 * Check the remote code (FSBL repository) in xplmi_status.h
		 * and the relevant service error (ie, xsecure_error.h) for
		 * detailed information.
		 */
		DMSG("PLM: plm status = 0x%" PRIx32 ", lib_status = 0x%" PRIx32,
		     (remote_status & 0xFFFF0000) >> 16,
		     (remote_status & 0x0000FFFF));

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
				       sizeof(struct versal_ipi_cmd));

	ipi.rsp = core_mmu_add_mapping(MEM_AREA_RAM_SEC,
				       ipi.buf + IPI_BUFFER_REMOTE_OFFSET +
				       IPI_BUFFER_RESP_OFFSET,
				       sizeof(struct versal_ipi_cmd));
	if (!ipi.req || !ipi.rsp)
		panic();

	mutex_init(&ipi.lock);

	return mbox_call(IPI_MAILBOX_OPEN, IPI_BLOCK);
}
early_init(versal_mbox_init);
