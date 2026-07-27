// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <drivers/hwkm.h>
#include <drivers/hwkm_errno.h>
#include <string.h>
#include <trace.h>

#include "hwkm/hwkm_derive_keys.h"

static const uint8_t l4_wrap_ctx[] =
	"HWKM : Hardware Key Manager provides hardware-based cryptography";
static const uint8_t optee_ctx[] = {
	0x51, 0x54, 0x45, 0x45, 0x20, 0x54, 0x72, 0x75,
	0x73, 0x74, 0x65, 0x64, 0x20, 0x41, 0x70, 0x70,
	0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x20, 0x4b, 0x65, 0x79, 0x20, 0x43, 0x54, 0x58,
};

static TEE_Result build_wrapping_kdf_ctx(const uint8_t *wrap_ctx,
					size_t wrap_ctx_len,
					uint8_t out_ctx[HWKM_MAX_CTX_SIZE])
{
	void *hash_ctx = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!wrap_ctx || !wrap_ctx_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_hash_alloc_ctx(&hash_ctx, TEE_ALG_SHA512);
	if (res)
		return res;

	res = crypto_hash_init(hash_ctx);
	if (res)
		goto out;

	res = crypto_hash_update(hash_ctx, optee_ctx, sizeof(optee_ctx));
	if (res)
		goto out;

	res = crypto_hash_update(hash_ctx, wrap_ctx, wrap_ctx_len);
	if (res)
		goto out;

	res = crypto_hash_final(hash_ctx, out_ctx, HWKM_MAX_CTX_SIZE);

out:
	crypto_hash_free_ctx(hash_ctx);
	return res;
}

/*
 * derive_l4_wrapping_key() - Derive L3 and L4 wrapping keys from UKDK_L2.
 *
 * Derives L3 into TZ_GENERAL_PURPOSE_SLOT2 and L4 into TZ_WRAP_KEY_SLOT.
 */
TEE_Result derive_l4_wrapping_key(void)
{
	uint8_t kdf_ctx[HWKM_MAX_CTX_SIZE] = { };
	struct hwkm_transaction t_kdf_l3 = {
		.cmd = {
			.op = HWKM_OP_SYSTEM_KDF,
			.kdf = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT2,
				.kdk = HWKM_SLOT_TZ_UKDK_L2,
				.policy = {
					.km_by_tz_allowed = true,
					.alg_allowed = HWKM_ALGO_AES256_CMAC,
					.enc_allowed = true,
					.key_type = HWKM_KEY_TYPE_KDK,
					.kdf_depth = 1,
					.security_lvl = HWKM_KEY_SECURITY_LVL_HW_KEY,
					.hw_destination = HWKM_KEY_DEST_KM_MASTER,
				},
				.bsve = {
					.enabled = true,
					.km_swc_en = true,
					.km_key_policy_ver_en = true,
					.km_apps_secure_en = true,
					.km_msa_secure_en = true,
					.km_child_key_policy_en = true,
				},
				.ctx_len = 0,
			},
		},
	};
	struct hwkm_transaction t_kdf_l4 = {
		.cmd = {
			.op = HWKM_OP_SYSTEM_KDF,
			.kdf = {
				.dks = HWKM_SLOT_TZ_WRAP_KEY_SLOT,
				.kdk = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT2,
				.policy = {
					.km_by_tz_allowed = true,
					.alg_allowed = HWKM_ALGO_AES256_SIV,
					.enc_allowed = true,
					.dec_allowed = true,
					.key_type = HWKM_KEY_TYPE_KWK,
					.kdf_depth = 0,
					.security_lvl = HWKM_KEY_SECURITY_LVL_HW_KEY,
					.hw_destination = HWKM_KEY_DEST_KM_MASTER,
				},
				.bsve = {
					.enabled = true,
					.km_swc_en = true,
					.km_key_policy_ver_en = true,
					.km_apps_secure_en = true,
					.km_msa_secure_en = true,
					.km_child_key_policy_en = true,
				},
				.ctx_len = 0,
			},
		},
	};
	struct hwkm_transaction t_clear_gp2 = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT2,
				.is_double_key = false,
			},
		},
	};
	int rc = HWKM_ERR_GENERIC;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = build_wrapping_kdf_ctx(l4_wrap_ctx, sizeof(l4_wrap_ctx) - 1,
				      kdf_ctx);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(t_kdf_l3.cmd.kdf.ctx, kdf_ctx, sizeof(kdf_ctx));
	t_kdf_l3.cmd.kdf.ctx_len = sizeof(kdf_ctx);
	memcpy(t_kdf_l4.cmd.kdf.ctx, kdf_ctx, sizeof(kdf_ctx));
	t_kdf_l4.cmd.kdf.ctx_len = sizeof(kdf_ctx);

	rc = hwkm_run_transactions(HWKM_KEY_DEST_KM_MASTER, 3,
				   (struct hwkm_transaction *const[]){
					&t_kdf_l3, &t_kdf_l4, &t_clear_gp2 });

	memset(t_kdf_l3.cmd.kdf.ctx, 0, sizeof(t_kdf_l3.cmd.kdf.ctx));
	memset(t_kdf_l4.cmd.kdf.ctx, 0, sizeof(t_kdf_l4.cmd.kdf.ctx));
	memset(kdf_ctx, 0, sizeof(kdf_ctx));

	if (rc) {
		res = hwkm_to_optee(rc);
		goto out_clear;

	}

	if (t_kdf_l3.rsp.status != HWKM_RSP_ERR_SUCCESS ||
	    t_kdf_l4.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE derive L4: l3=0x%x l4=0x%x",
		     (unsigned int)t_kdf_l3.rsp.status,
		     (unsigned int)t_kdf_l4.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (t_clear_gp2.rsp.status != HWKM_RSP_ERR_SUCCESS &&
	    t_clear_gp2.rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) {
		EMSG("ICE derive L4 clear L3: gp2=0x%x",
		     (unsigned int)t_clear_gp2.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	res = TEE_SUCCESS;
out_clear:
	/*
	 * If any of the above transactions fail, make an attempt
	 * to clear the TZ_GENERAL_PURPOSE_SLOT2 since it may have
	 * been left with the key material.
	 */
	t_clear_gp2.hdl = NULL;
	hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear_gp2);
out:
	return res;
}

/* clear_l4_wrapping_key() - Clear the L4 wrapping slot. */
TEE_Result clear_l4_wrapping_key(void)
{
	struct hwkm_transaction t_clear_wrap = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = HWKM_SLOT_TZ_WRAP_KEY_SLOT,
				.is_double_key = true,
			},
		},
	};
	int rc = HWKM_ERR_GENERIC;

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear_wrap);
	if (rc)
		return hwkm_to_optee(rc);

	if (t_clear_wrap.rsp.status != HWKM_RSP_ERR_SUCCESS &&
	    t_clear_wrap.rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) {
		EMSG("ICE clear L4: wrap=0x%x",
		     (unsigned int)t_clear_wrap.rsp.status);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
