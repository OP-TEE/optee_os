// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/hwkm.h>
#include <drivers/hwkm_errno.h>
#include <kernel/mutex.h>
#include <string.h>
#include <trace.h>

#include "hwkm/hwkm_derive_keys.h"
#include "hwkm/ice_hwkm.h"

/*
 * import_and_wrap_with_hw_key() - Import caller key bytes then wrap under L4 key.
 *
 * Writes caller key material into TZ_GENERAL_PURPOSE_SLOT1, derives L3 then
 * L4 wrapping keys from TZ_UKDK_L2, exports wrapped blob, and clears
 * transient slots.
 */
TEE_Result import_and_wrap_with_hw_key(const uint8_t *in_key, size_t in_key_len,
				       uint8_t *out_blob, size_t *out_blob_len)
{
	const struct hwkm_key_policy import_policy = {
		.km_by_tz_allowed = true,
		.km_by_nsec_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_CMAC,
		.enc_allowed = true,
		.key_type = HWKM_KEY_TYPE_KDK,
		.kdf_depth = 1,
		.wrap_export_allowed = true,
		.swap_export_allowed = true,
		.wrap_with_tpkey_allowed = true,
		.security_lvl = HWKM_KEY_SECURITY_LVL_SW_KEY,
		.hw_destination = HWKM_KEY_DEST_ICE_SLAVE,
	};
	struct hwkm_transaction t_import = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_RDWR,
			.rdwr = {
				.slot = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.is_write = true,
				.policy = import_policy,
			},
		},
	};
	struct hwkm_transaction t_wrap = {
		.cmd = {
			.op = HWKM_OP_KEY_WRAP_EXPORT,
			.wrap = {
				.sks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.kwk = HWKM_SLOT_TZ_WRAP_KEY_SLOT,
			},
		},
	};
	struct hwkm_transaction t_clear_gp1 = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.is_double_key = false,
			},
		},
	};
	int rc = HWKM_ERR_GENERIC;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct hwkm_drv_ctx *drv = hwkm_get_context();
	if (!drv)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!in_key || !in_key_len || !out_blob || !out_blob_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_key_len > HWKM_MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*out_blob_len < HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(t_import.cmd.rdwr.key, in_key, in_key_len);

	mutex_lock(&drv->hwkm_lock);
	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_import);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_import.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE import L4: import=0x%x", (unsigned int)t_import.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	res = derive_l4_wrapping_key();
	if (res != TEE_SUCCESS)
		goto cleanup;

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_wrap);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_wrap.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE import L4: wrap=0x%x", (unsigned int)t_wrap.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	memcpy(out_blob, t_wrap.rsp.wrap.wkb, HWKM_MAX_BLOB_SIZE);
	*out_blob_len = HWKM_MAX_BLOB_SIZE;
	res = TEE_SUCCESS;

cleanup:
	(void)clear_l4_wrapping_key();
	(void)hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear_gp1);
	mutex_unlock(&drv->hwkm_lock);

	memset(t_import.cmd.rdwr.key, 0, sizeof(t_import.cmd.rdwr.key));
	memset(t_wrap.rsp.wrap.wkb, 0, sizeof(t_wrap.rsp.wrap.wkb));
	return res;
}

/*
 * generate_hw_wrapped_key() - Generate and wrap a key with UKDK-derived L4 key.
 *
 * Generates key material in TZ_GENERAL_PURPOSE_SLOT1, derives L3 then L4
 * wrapping keys from TZ_UKDK_L2, exports wrapped blob, and clears transient
 * slots.
 */
TEE_Result generate_hw_wrapped_key(uint8_t *out_blob, size_t *out_blob_len)
{
	const struct hwkm_key_policy key_policy = {
		.km_by_tz_allowed = true,
		.km_by_nsec_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_CMAC,
		.enc_allowed = true,
		.key_type = HWKM_KEY_TYPE_KDK,
		.kdf_depth = 1,
		.wrap_export_allowed = true,
		.swap_export_allowed = true,
		.wrap_with_tpkey_allowed = true,
		.security_lvl = HWKM_KEY_SECURITY_LVL_SW_KEY,
		.hw_destination = HWKM_KEY_DEST_ICE_SLAVE,
	};
	struct hwkm_transaction t_keygen = {
		.cmd = {
			.op = HWKM_OP_NIST_KEYGEN,
			.keygen = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.policy = key_policy,
			},
		},
	};
	struct hwkm_transaction t_wrap = {
		.cmd = {
			.op = HWKM_OP_KEY_WRAP_EXPORT,
			.wrap = {
				.sks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.kwk = HWKM_SLOT_TZ_WRAP_KEY_SLOT,
			},
		},
	};
	struct hwkm_transaction t_clear_gp1 = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.is_double_key = false,
			},
		},
	};
	int rc = HWKM_ERR_GENERIC;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct hwkm_drv_ctx *drv = hwkm_get_context();
	if (!drv)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!out_blob || !out_blob_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*out_blob_len < HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	mutex_lock(&drv->hwkm_lock);
	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_keygen);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_keygen.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE gen L4: keygen=0x%x", (unsigned int)t_keygen.rsp.status);
		goto cleanup;
	}

	res = derive_l4_wrapping_key();
	if (res != TEE_SUCCESS)
		goto cleanup;

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_wrap);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_wrap.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE gen L4: wrap=0x%x", (unsigned int)t_wrap.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	memcpy(out_blob, t_wrap.rsp.wrap.wkb, HWKM_MAX_BLOB_SIZE);
	*out_blob_len = HWKM_MAX_BLOB_SIZE;
	res = TEE_SUCCESS;

cleanup:
	(void)clear_l4_wrapping_key();
	(void)hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear_gp1);
	mutex_unlock(&drv->hwkm_lock);

	memset(t_wrap.rsp.wrap.wkb, 0, sizeof(t_wrap.rsp.wrap.wkb));
	return res;
}
