// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tmel_km_client.h>
#include <trace.h>
#include <util.h>

/*
 * Serial-number fuse lives in the QFPROM region. Map the page that holds it so
 * tee_otp_get_die_id() can read it; the qfprom driver is not present otherwise.
 */
register_phys_mem(MEM_AREA_IO_SEC,
		  QCOM_SERIAL_NUM_FUSE_ADDR & ~SMALL_PAGE_MASK,
		  SMALL_PAGE_SIZE);

_Static_assert(HW_UNIQUE_KEY_LENGTH == 16 || HW_UNIQUE_KEY_LENGTH == 32,
	       "HW_UNIQUE_KEY_LENGTH must be 16 or 32 bytes");

/*
 * Derives a key with TME's KDF, distributes it to TCSR endpoint slot 0, then
 * reads it back from the TCSR registers.
 */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	struct tme_kdf_spec kdf = {
		.kdf_algo = TME_KAL_KDF_NIST,
		.security_context = TME_KSC_SOC_SEC_BOOT_STATE |
				    TME_KSC_TME_LIFECYCLE_STATE |
				    TME_KSC_SOC_DEBUG_STATE |
				    TME_KSC_CHILD_KEY_POLICY |
				    TME_KSC_SW_CONTEXT,
		.prf_digest_algo = TME_KAL_SHA512_HMAC,
		.input_key = TME_KID_CHIP_RAND_BASE,
		.l2_key = TME_KID_L2_KEYWRAPSVC,
	};
	uint32_t key[8] = { }; /* room for up to 256 bits */
	uint32_t handle = TME_KEY_HANDLE_INVALID;
	TEE_Result clear_res = TEE_ERROR_GENERIC;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t algo = TME_KAL_AES128_ECB;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (HW_UNIQUE_KEY_LENGTH == 32)
		algo = TME_KAL_AES256_ECB;

	res = tmel_km_create_key_policy(HW_UNIQUE_KEY_LENGTH * 8, algo,
					TME_KD_TCSR_ENDPOINT, TME_KLI_NP_CU,
					&kdf.policy);
	if (res)
		return res;

	res = tmel_km_derive_key(&kdf, &handle);
	if (res)
		return res;

	if (handle == TME_KEY_HANDLE_INVALID) {
		EMSG("Key derivation returned an invalid handle");
		return TEE_ERROR_GENERIC;
	}

	res = tmel_km_distribute_key(handle, TME_KD_TCSR_ENDPOINT, 0);
	if (res)
		goto out_clear;

	res = tmel_km_read_tcsr_key_and_clear(key, sizeof(key), 0);
	if (res)
		goto out_clear;

	memcpy(hwkey->data, key, HW_UNIQUE_KEY_LENGTH);

out_clear:
	memzero_explicit(key, sizeof(key));

	clear_res = tmel_km_clear_key(handle);
	if (clear_res) {
		EMSG("tmel_km_clear_key failed");
		/* Don't hand out a key whose handle is still live in TME */
		if (!res) {
			memzero_explicit(hwkey->data, HW_UNIQUE_KEY_LENGTH);
			res = clear_res;
		}
	}

	return res;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	vaddr_t fuse_base = 0;
	uint32_t die_id = 0;

	if (!buffer || !len)
		return -1;

	fuse_base = core_mmu_get_va(QCOM_SERIAL_NUM_FUSE_ADDR,
				    MEM_AREA_IO_SEC, sizeof(uint32_t));
	if (!fuse_base) {
		EMSG("Failed to map die ID fuse register");
		return -1;
	}

	die_id = io_read32(fuse_base);

	memset(buffer, 0, len);
	memcpy(buffer, &die_id, MIN(len, sizeof(die_id)));

	return 0;
}
