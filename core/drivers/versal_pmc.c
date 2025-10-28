// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 *
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#include <config.h>
#include <drivers/versal_pmc.h>
#include <initcall.h>

#ifdef CFG_VERSAL_TRACE_PMC
static const char *const nvm_id[] = {
	[0] = "API_FEATURES",
	[1] = "BBRAM_WRITE_AES_KEY",
	[2] = "BBRAM_ZEROIZE",
	[3] = "BBRAM_WRITE_USER_DATA",
	[4] = "BBRAM_READ_USER_DATA",
	[5] = "BBRAM_LOCK_WRITE_USER_DATA",
#if defined(PLATFORM_FLAVOR_net)
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

static void versal_pmc_call_trace(uint32_t call)
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

	IMSG("--- pmc: service: %s\t call: %s", module[mid],
	     val ? val : "Invalid");
};
#else
static void versal_pmc_call_trace(uint32_t call __unused)
{}
#endif

static struct versal_ipi ipi_pmc;

TEE_Result versal_pmc_notify(struct versal_ipi_cmd *cmd,
			     struct versal_ipi_cmd *rsp, uint32_t *err)
{
	TEE_Result ret = TEE_SUCCESS;

	if (IS_ENABLED(CFG_VERSAL_TRACE_PMC))
		versal_pmc_call_trace(cmd->data[0]);

	ret = versal_mbox_notify(&ipi_pmc, cmd, rsp, err);
	if (ret && err) {
		/*
		 * Check the remote code (FSBL repository) in xplmi_status.h
		 * and the relevant service error (ie, xsecure_error.h) for
		 * detailed information.
		 */
		DMSG("PLM: plm status = 0x%" PRIx32 ", lib_status = 0x%" PRIx32,
		     (*err & 0xFFFF0000) >> 16,
		     (*err & 0x0000FFFF));

		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

static TEE_Result versal_pmc_init(void)
{
	uint32_t lcl = 0;

	switch (CFG_VERSAL_PMC_IPI_ID) {
	case 0:
		lcl = VERSAL_IPI_ID_0;
		break;
	case 1:
		lcl = VERSAL_IPI_ID_1;
		break;
	case 2:
		lcl = VERSAL_IPI_ID_2;
		break;
	case 3:
		lcl = VERSAL_IPI_ID_3;
		break;
	case 4:
		lcl = VERSAL_IPI_ID_4;
		break;
	case 5:
		lcl = VERSAL_IPI_ID_5;
		break;
	default:
		EMSG("Invalid IPI requested");
		return TEE_ERROR_GENERIC;
	}

	return versal_mbox_open(lcl, VERSAL_IPI_ID_PMC, &ipi_pmc);
}
early_init(versal_pmc_init);
