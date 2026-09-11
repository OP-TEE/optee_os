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
#include <trace.h>
#include <util.h>

#include <tmekm_client.h>

/*
 * Serial-number fuse lives in the QFPROM region. Map the page that holds it so
 * tee_otp_get_die_id() can read it; the qfprom driver is not present otherwise.
 */
register_phys_mem(MEM_AREA_IO_SEC,
		  QCOM_SERIAL_NUM_FUSE_ADDR & ~SMALL_PAGE_MASK,
		  SMALL_PAGE_SIZE);

/*
 * tee_otp_get_hw_unique_key() - derive the Hardware Unique Key via TME-Lite.
 *
 * Derives a key with TME's KDF, distributes it to TCSR endpoint slot 0, then
 * reads it back from the TCSR registers. The key size follows
 * HW_UNIQUE_KEY_LENGTH.
 */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t key_length_bits = HW_UNIQUE_KEY_LENGTH * 8;
	uint32_t key_handle = TME_KEY_HANDLE_INVALID;
	uint32_t tcsr_key[8] = { }; /* room for up to 256 bits */
	struct tme_key_policy key_policy = { };
	struct tme_kdf_spec kdf_spec = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t algo_mode = 0;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_length_bits == 128) {
		algo_mode = TME_KAL_AES128_ECB;
	} else if (key_length_bits == 256) {
		algo_mode = TME_KAL_AES256_ECB;
	} else {
		EMSG("Unsupported key length: %u bits", key_length_bits);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	tme_km_create_key_policy(key_length_bits, algo_mode,
				 TME_KD_TCSR_ENDPOINT, TME_KLI_NP_CU,
				 &key_policy);

	kdf_spec.kdf_algo = TME_KAL_KDF_NIST;
	kdf_spec.policy = key_policy;
	kdf_spec.security_context = TME_KSC_SOCSecBootState |
				    TME_KSC_TMELifecycleState |
				    TME_KSC_SOCDebugState |
				    TME_KSC_ChildKeyPolicy |
				    TME_KSC_SWContext;
	kdf_spec.prf_digest_algo = TME_KAL_SHA512_HMAC;
	kdf_spec.input_key = TME_KID_CHIP_RAND_BASE;
	kdf_spec.l2_key = TME_KID_L2_KEYWRAPSVC;

	res = tme_km_derive_key(&kdf_spec, &key_handle);
	if (res)
		return res;

	if (key_handle == TME_KEY_HANDLE_INVALID) {
		EMSG("Key derivation returned an invalid handle");
		return TEE_ERROR_GENERIC;
	}

	res = tme_km_distribute_key(key_handle, TME_KD_TCSR_ENDPOINT, 0);
	if (res)
		goto out_clear;

	res = tme_km_read_tcsr_key_and_clear(tcsr_key, sizeof(tcsr_key), 0);
	if (res)
		goto out_clear;

	memcpy(hwkey->data, tcsr_key, HW_UNIQUE_KEY_LENGTH);
	memzero_explicit(tcsr_key, sizeof(tcsr_key));

out_clear:
	if (tme_km_clear_key(key_handle))
		EMSG("tme_km_clear_key failed");

	return res;
}

/*
 * tee_otp_get_die_id() - read the die identifier from the serial-number fuse.
 */
int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	vaddr_t fuse_base = 0;
	size_t copy_len = 0;
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

	copy_len = MIN(len, sizeof(die_id));
	memcpy(buffer, &die_id, copy_len);

	if (len > sizeof(die_id))
		memset(buffer + sizeof(die_id), 0, len - sizeof(die_id));

	return 0;
}
