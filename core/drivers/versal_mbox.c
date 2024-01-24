// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 *
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <tee/cache.h>
#include "drivers/versal_mbox.h"

#if defined(PLATFORM_FLAVOR_net)
#define IPI_REGS_BASEADDR		0xEB300000
#define IPI_BUFFER_BASEADDR		0xEB3F0000
#else
#define IPI_REGS_BASEADDR		0xFF300000
#define IPI_BUFFER_BASEADDR		0xFF3F0000
#endif

#define IPI_SIZE		0x10000

#define IPI_TRIG_OFFSET		0x00
#define IPI_OBR_OFFSET		0x04
#define IPI_ISR_OFFSET		0x10
#define IPI_IMR_OFFSET		0x14
#define IPI_IER_OFFSET		0x18
#define IPI_IDR_OFFSET		0x1C

#define IPI_PMC_TRIG_BIT	BIT(1)
#define IPI0_TRIG_BIT		BIT(2)
#define IPI1_TRIG_BIT		BIT(3)
#define IPI2_TRIG_BIT		BIT(4)
#define IPI3_TRIG_BIT		BIT(5)
#define IPI4_TRIG_BIT		BIT(6)
#define IPI5_TRIG_BIT		BIT(7)

/* Interrupt Config Registers */
#define IPI_PMC_REG_BASE	(IPI_REGS_BASEADDR + 0x20000)
#define IPI0_REG_BASE		(IPI_REGS_BASEADDR + 0x30000)
#define IPI1_REG_BASE		(IPI_REGS_BASEADDR + 0x40000)
#define IPI2_REG_BASE		(IPI_REGS_BASEADDR + 0x50000)
#define IPI3_REG_BASE		(IPI_REGS_BASEADDR + 0x60000)
#define IPI4_REG_BASE		(IPI_REGS_BASEADDR + 0x70000)
#define IPI5_REG_BASE		(IPI_REGS_BASEADDR + 0x80000)

/* Buffers */
#define IPI_BUFFER_PMC_BASE			(IPI_BUFFER_BASEADDR + 0x200)
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

static const struct versal_ipi_config {
	uint32_t ipi_bit_mask;
	uint32_t ipi_reg_base;
	uint32_t ipi_buf_base;
	uint32_t ipi_remote_offset;
} versal_ipi_table[] = {
	/* PMC IPI */
	[IPI_ID_PMC] = {
		.ipi_bit_mask = IPI_PMC_TRIG_BIT,
		.ipi_reg_base = IPI_PMC_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_PMC_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_PMC_OFFSET,
	},

	/* IPI0 IPI */
	[IPI_ID_0] = {
		.ipi_bit_mask = IPI0_TRIG_BIT,
		.ipi_reg_base = IPI0_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_0_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_0_OFFSET,
	},

	/* IPI1 IPI */
	[IPI_ID_1] = {
		.ipi_bit_mask = IPI1_TRIG_BIT,
		.ipi_reg_base = IPI1_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_1_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_1_OFFSET,
	},

	/* IPI2 IPI */
	[IPI_ID_2] = {
		.ipi_bit_mask = IPI2_TRIG_BIT,
		.ipi_reg_base = IPI2_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_2_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_2_OFFSET,
	},

	/* IPI3 IPI */
	[IPI_ID_3] = {
		.ipi_bit_mask = IPI3_TRIG_BIT,
		.ipi_reg_base = IPI3_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_3_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_3_OFFSET,
	},

	/* IPI4 IPI */
	[IPI_ID_4] = {
		.ipi_bit_mask = IPI4_TRIG_BIT,
		.ipi_reg_base = IPI4_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_4_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_4_OFFSET,
	},

	/* IPI5 IPI */
	[IPI_ID_5] = {
		.ipi_bit_mask = IPI5_TRIG_BIT,
		.ipi_reg_base = IPI5_REG_BASE,
		.ipi_buf_base = IPI_BUFFER_APU_ID_5_BASE,
		.ipi_remote_offset = IPI_BUFFER_TARGET_ID_5_OFFSET,
	},
};

#define IPI_REG_BASE(I) (versal_ipi_table[I].ipi_reg_base)
#define IPI_BIT_MASK(I) (versal_ipi_table[I].ipi_bit_mask)
#define IPI_BUF_BASE(I) (versal_ipi_table[I].ipi_buf_base)
#define IPI_REMOTE_OFFSET(I) (versal_ipi_table[I].ipi_remote_offset)

static const char *const nvm_id[] = {
	[0] = "API_FEATURES",
	[1] = "BBRAM_WRITE_AES_KEY",
	[2] = "BBRAM_ZEROIZE",
	[3] = "BBRAM_WRITE_USER_DATA",
	[4] = "BBRAM_READ_USER_DATA",
	[5] = "BBRAM_LOCK_WRITE_USER_DATA",
#ifdef PLATFORM_FLAVOR_net
	[6] = "BBRAM_WRITE_AES_KEY_FROM_PLOAD",
	[7] = "EFUSE_WRITE_AES_KEY",
	[8] = "EFUSE_WRITE_AES_KEY_FROM_PLOAD",
	[9] = "EFUSE_WRITE_PPK_HASH",
	[10] = "EFUSE_WRITE_PPK_HASH_FROM_PLOAD",
	[11] = "EFUSE_WRITE_IV",
	[12] = "EFUSE_WRITE_IV_FROM_PLOAD",
	[13] = "EFUSE_WRITE_GLITCH_CONFIG",
	[14] = "EFUSE_WRITE_DEC_ONLY",
	[15] = "EFUSE_WRITE_REVOCATION_ID",
	[16] = "EFUSE_WRITE_OFFCHIP_REVOKE_ID",
	[17] = "EFUSE_WRITE_MISC_CTRL_BITS",
	[18] = "EFUSE_WRITE_SEC_CTRL_BITS",
	[19] = "EFUSE_WRITE_MISC1_CTRL_BITS",
	[20] = "EFUSE_WRITE_BOOT_ENV_CTRL_BITS",
	[21] = "EFUSE_WRITE_FIPS_INFO",
	[22] = "EFUSE_WRITE_UDS_FROM_PLOAD",
	[23] = "EFUSE_WRITE_DME_KEY_FROM_PLOAD",
	[24] = "EFUSE_WRITE_DME_REVOKE",
	[25] = "EFUSE_WRITE_PLM_UPDATE",
	[26] = "EFUSE_WRITE_BOOT_MODE_DISABLE",
	[27] = "EFUSE_WRITE_CRC",
	[28] = "EFUSE_WRITE_DME_MODE",
	[29] = "EFUSE_WRITE_PUF_HD_FROM_PLOAD",
	[30] = "EFUSE_WRITE_PUF",
	[31] = "EFUSE_WRITE_ROM_RSVD",
	[32] = "EFUSE_WRITE_PUF_CTRL_BITS",
	[33] = "EFUSE_READ_CACHE",
	[34] = "EFUSE_RELOAD_N_PRGM_PROT_BITS",
	[35] = "EFUSE_INVALID",
#else
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
#endif
};

static const char *const crypto_id[] = {
	[0] = "FEATURES",
	[1] = "RSA_SIGN_VERIFY",
	[2] = "RSA_PUBLIC_ENCRYPT",
	[3] = "RSA_PRIVATE_DECRYPT",
	[4] = "SHA3_UPDATE",
	[5] = "ELLIPTIC_GENERATE_PUBLIC_KEY",
	[6] = "ELLIPTIC_GENERATE_SIGN",
	[7] = "ELLIPTIC_VALIDATE_PUBLIC_KEY",
	[8] = "ELLIPTIC_VERIFY_SIGN",
	[9] = "AES_INIT",
	[10] = "AES_OP_INIT",
	[11] = "AES_UPDATE_AAD",
	[12] = "AES_ENCRYPT_UPDATE",
	[13] = "AES_ENCRYPT_FINAL",
	[14] = "AES_DECRYPT_UPDATE",
	[15] = "AES_DECRYPT_FINAL",
	[16] = "AES_KEY_ZERO",
	[17] = "AES_WRITE_KEY",
	[18] = "AES_LOCK_USER_KEY",
	[19] = "AES_KEK_DECRYPT",
	[20] = "AES_SET_DPA_CM",
	[21] = "KAT",
	[22] = "TRNG_GENERATE",
	[23] = "AES_PERFORM_OPERATION",
	[24] = "MAX",
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

static TEE_Result versal_mbox_write_req(struct versal_ipi *ipi,
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

static TEE_Result versal_mbox_read_rsp(struct versal_ipi *ipi,
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

TEE_Result versal_mbox_open(uint32_t local, uint32_t remote,
			    struct versal_ipi *ipi)
{
	assert(ipi);

	ipi->regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						  IPI_REG_BASE(local),
						  IPI_SIZE);

	ipi->req = core_mmu_add_mapping(MEM_AREA_IO_SEC,
					IPI_BUF_BASE(local) +
					IPI_REMOTE_OFFSET(remote) +
					IPI_BUFFER_REQ_OFFSET,
					sizeof(struct versal_ipi_cmd));

	ipi->rsp = core_mmu_add_mapping(MEM_AREA_IO_SEC,
					IPI_BUF_BASE(local) +
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

	return TEE_SUCCESS;
}

TEE_Result versal_mbox_close(struct versal_ipi *ipi)
{
	assert(ipi);

	io_write32(ipi->regs + IPI_IDR_OFFSET,
		   IPI_BIT_MASK(ipi->rmt));

	return TEE_SUCCESS;
}

TEE_Result versal_mbox_alloc(size_t len, const void *init,
			     struct versal_mbox_mem *mem)
{
	mem->buf = memalign(CACHELINE_LEN, ROUNDUP(len, CACHELINE_LEN));
	if (!mem->buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(mem->buf, 0, ROUNDUP(len, CACHELINE_LEN));

	if (init)
		memcpy(mem->buf, init, len);

	mem->alloc_len = ROUNDUP(len, CACHELINE_LEN);
	mem->len = len;

	return TEE_SUCCESS;
}

void versal_mbox_free(struct versal_mbox_mem *mem)
{
	assert(mem);

	free(mem->buf);
	mem->buf = NULL;
}

TEE_Result versal_mbox_notify(struct versal_ipi *ipi,
			      struct versal_ipi_cmd *cmd,
			      struct versal_ipi_cmd *rsp, uint32_t *err)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t status = 0;

	mutex_lock(&ipi->lock);

	ret = versal_mbox_write_req(ipi, cmd);
	if (ret) {
		EMSG("Can't write the request command");
		goto out;
	}

	/* Trigger interrupt to remote */
	io_write32(ipi->regs + IPI_TRIG_OFFSET, IPI_BIT_MASK(ipi->rmt));

	/* Wait for remote to acknowledge the interrupt */
	if (IO_READ32_POLL_TIMEOUT(ipi->regs + IPI_OBR_OFFSET, status,
				   !(status & IPI_BIT_MASK(ipi->rmt)), 1,
				   CFG_VERSAL_MBOX_TIMEOUT)) {
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	ret = versal_mbox_read_rsp(ipi, cmd, rsp, &status);
	if (ret)
		EMSG("Can't read the remote response");

	if (status) {
		if (err)
			*err = status;

		ret = TEE_ERROR_GENERIC;
	}
out:
	mutex_unlock(&ipi->lock);

	return ret;
}

static struct versal_ipi ipi_pmc;

TEE_Result versal_mbox_notify_pmc(struct versal_ipi_cmd *cmd,
				  struct versal_ipi_cmd *rsp, uint32_t *err)
{
	TEE_Result ret = TEE_SUCCESS;

	if (IS_ENABLED(CFG_VERSAL_TRACE_MBOX))
		versal_mbox_call_trace(cmd->data[0]);

	ret = versal_mbox_notify(&ipi_pmc, cmd, rsp, err);

	if (ret != TEE_SUCCESS && err) {
		/*
		 * Check the remote code (FSBL repository) in xplmi_status.h
		 * and the relevant service error (ie, xsecure_error.h) for
		 * detailed information.
		 */
		DMSG("PLM: plm status = 0x%" PRIx32 ", lib_status = 0x%" PRIx32,
		     (*err & 0xFFFF0000) >> 16,
		     (*err & 0x0000FFFF));
	}

	return ret;
}

static TEE_Result versal_mbox_init(void)
{
	uint32_t lcl = 0;

	switch (CFG_VERSAL_MBOX_IPI_ID) {
	case 0:
		lcl = IPI_ID_0;
		break;
	case 1:
		lcl = IPI_ID_1;
		break;
	case 2:
		lcl = IPI_ID_2;
		break;
	case 3:
		lcl = IPI_ID_3;
		break;
	case 4:
		lcl = IPI_ID_4;
		break;
	case 5:
		lcl = IPI_ID_5;
		break;
	default:
		EMSG("Invalid IPI requested");
		return TEE_ERROR_GENERIC;
	}

	return versal_mbox_open(lcl, IPI_ID_PMC, &ipi_pmc);
}
early_init(versal_mbox_init);
