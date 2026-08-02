// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <drivers/hwkm.h>
#include <drivers/hwkm_errno.h>
#include <crypto/crypto.h>
#include <io.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <trace.h>

#include "ice_config.h"
#include "hwkm/hwkm_derive_keys.h"
#include "hwkm/ice_hwkm.h"

#define HWKM_ICE_SLAVE_GP_SLOT          140U
#define HWKM_ICE_DEFAULT_TPKEY_SLOT     146U
#define HWKM_ICE_MAP_SLOT(pipe)         ((uint8_t)(((pipe) * 2U) + 10U))
#define HWKM_CTX_ALIGN_BYTES            8U

static inline size_t round_up_ctx_len(size_t len)
{
	return (len + (HWKM_CTX_ALIGN_BYTES - 1U)) & ~(HWKM_CTX_ALIGN_BYTES - 1U);
}

static const uint8_t inlinecrypt_ctx[] = "inline encryption key";

static uint8_t g_ephemeral_ctx[HWKM_EPHEMERAL_CTX_SIZE] = { 0 };
static bool g_ephemeral_ctx_set = false;

static TEE_Result get_or_init_ephemeral_ctx(const uint8_t **ctx,
					    size_t *ctx_len)
{
	if (!ctx || !ctx_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_ephemeral_ctx_set) {
		if (crypto_rng_read(g_ephemeral_ctx,
				    sizeof(g_ephemeral_ctx)) != TEE_SUCCESS)
			return TEE_ERROR_GENERIC;

		g_ephemeral_ctx_set = true;
	}

	*ctx = g_ephemeral_ctx;
	*ctx_len = sizeof(g_ephemeral_ctx);
	return TEE_SUCCESS;
}

/*
 * export_tpkey_wrapped_blob_from_ephemeral() - Unwrap input blob under
 * ephemeral wrapping key, then re-wrap/export under TPKEY.
 */
static TEE_Result export_tpkey_wrapped_blob_from_ephemeral(const uint8_t *in_blob,
							   size_t in_blob_len,
							   uint8_t *out_blob,
							   size_t *out_blob_len)
{
	const uint8_t *ephemeral_ctx = NULL;
	size_t ephemeral_ctx_len = 0;
	struct hwkm_transaction t_unwrap = {
		.cmd = {
			.op = HWKM_OP_KEY_UNWRAP_IMPORT,
			.unwrap = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.kwk = HWKM_SLOT_TZ_WRAP_KEY_SLOT,
			},
		},
	};
	struct hwkm_transaction t_wrap_tpkey = {
		.cmd = {
			.op = HWKM_OP_KEY_WRAP_EXPORT,
			.wrap = {
				.sks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.kwk = HWKM_SLOT_TPKEY_SLOT,
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

	if (!in_blob || !out_blob || !out_blob_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_blob_len != HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*out_blob_len < HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	res = get_or_init_ephemeral_ctx(&ephemeral_ctx, &ephemeral_ctx_len);
	if (res != TEE_SUCCESS)
		return res;

	mutex_lock(&drv->hwkm_lock);
	res = derive_ephemeral_wrapping_key(ephemeral_ctx, ephemeral_ctx_len);
	if (res != TEE_SUCCESS)
		goto cleanup;

	memcpy(t_unwrap.cmd.unwrap.wkb, in_blob, HWKM_MAX_BLOB_SIZE);

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_unwrap);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_unwrap.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE tpwrap unwrap failed: status=0x%x",
		     (unsigned int)t_unwrap.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_wrap_tpkey);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_wrap_tpkey.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE tpwrap export failed: status=0x%x",
		     (unsigned int)t_wrap_tpkey.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	memcpy(out_blob, t_wrap_tpkey.rsp.wrap.wkb, HWKM_MAX_BLOB_SIZE);
	*out_blob_len = HWKM_MAX_BLOB_SIZE;
	res = TEE_SUCCESS;

cleanup:
	(void)clear_ephemeral_key();
	(void)hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear_gp1);
	mutex_unlock(&drv->hwkm_lock);

	memset(t_unwrap.cmd.unwrap.wkb, 0, sizeof(t_unwrap.cmd.unwrap.wkb));
	memset(t_wrap_tpkey.rsp.wrap.wkb, 0, sizeof(t_wrap_tpkey.rsp.wrap.wkb));
	return res;
}

/*
 * program_ice_slave_from_tpkey_blob() - On ICE_SLAVE, import TPKEY-wrapped
 * blob into staging slot and derive final key into mapped ICE key slot.
 */
static TEE_Result program_ice_slave_from_tpkey_blob(uint32_t pipe,
						    const uint8_t *tpkey_blob,
						    size_t tpkey_blob_len)
{
	uint8_t mapped_slot = 0;
	size_t ctx_len = round_up_ctx_len(sizeof(inlinecrypt_ctx) - 1);
	struct hwkm_transaction t_clear_mapped = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = 0,
				.is_double_key = true,
			},
		},
	};
	struct hwkm_transaction t_clear_gp = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = HWKM_ICE_SLAVE_GP_SLOT,
				.is_double_key = false,
			},
		},
	};
	struct hwkm_transaction t_import = {
		.cmd = {
			.op = HWKM_OP_KEY_UNWRAP_IMPORT,
			.unwrap = {
				.dks = HWKM_ICE_SLAVE_GP_SLOT,
				.kwk = HWKM_ICE_DEFAULT_TPKEY_SLOT,
			},
		},
	};
	struct hwkm_transaction t_kdf_ice = {
		.cmd = {
			.op = HWKM_OP_SYSTEM_KDF,
			.kdf = {
				.dks = 0,
				.kdk = HWKM_ICE_SLAVE_GP_SLOT,
				.policy = {
					.km_by_tz_allowed = true,
					.alg_allowed = HWKM_ALGO_AES256_XTS,
					.enc_allowed = true,
					.dec_allowed = true,
					.key_type = HWKM_KEY_TYPE_GENERIC_KEY,
					.security_lvl = HWKM_KEY_SECURITY_LVL_SW_KEY,
					.hw_destination = HWKM_KEY_DEST_ICE_SLAVE,
				},
				.bsve = {
					.enabled = true,
					.km_swc_en = true,
					.km_child_key_policy_en = true,
				},
				.ctx_len = 0,
			},
		},
	};
	int rc = HWKM_ERR_GENERIC;
	struct hwkm_drv_ctx *drv = hwkm_get_context();
	if (!drv)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!tpkey_blob || tpkey_blob_len != HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (pipe >= ICE_MAX_KEY_IDX)
		return TEE_ERROR_BAD_PARAMETERS;

	mapped_slot = HWKM_ICE_MAP_SLOT(pipe);
	t_clear_mapped.cmd.clear.dks = mapped_slot;
	t_kdf_ice.cmd.kdf.dks = mapped_slot;

	memset(t_kdf_ice.cmd.kdf.ctx, 0, sizeof(t_kdf_ice.cmd.kdf.ctx));
	memcpy(t_kdf_ice.cmd.kdf.ctx, inlinecrypt_ctx, sizeof(inlinecrypt_ctx) - 1);
	t_kdf_ice.cmd.kdf.ctx_len = ctx_len;

	memcpy(t_import.cmd.unwrap.wkb, tpkey_blob, HWKM_MAX_BLOB_SIZE);

	mutex_lock(&drv->hwkm_lock);
	rc = hwkm_run_transactions(HWKM_KEY_DEST_ICE_SLAVE, 4,
				   (struct hwkm_transaction *const[]){
					&t_clear_gp, &t_clear_mapped,
					&t_import, &t_kdf_ice });

	mutex_unlock(&drv->hwkm_lock);
	memset(t_import.cmd.unwrap.wkb, 0, sizeof(t_import.cmd.unwrap.wkb));
	memset(t_kdf_ice.cmd.kdf.ctx, 0, sizeof(t_kdf_ice.cmd.kdf.ctx));

	if (rc)
		return hwkm_to_optee(rc);

	if ((t_clear_gp.rsp.status != HWKM_RSP_ERR_SUCCESS &&
	     t_clear_gp.rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) ||
	    (t_clear_mapped.rsp.status != HWKM_RSP_ERR_SUCCESS &&
	     t_clear_mapped.rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) ||
	    t_import.rsp.status != HWKM_RSP_ERR_SUCCESS ||
	    t_kdf_ice.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE slave prog failed: clear_gp=0x%x clear_dst=0x%x import=0x%x kdf=0x%x",
		     (unsigned int)t_clear_gp.rsp.status,
		     (unsigned int)t_clear_mapped.rsp.status,
		     (unsigned int)t_import.rsp.status,
		     (unsigned int)t_kdf_ice.rsp.status);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * program_content_key_using_hwkm() - Top-level helper for ICE key programming.
 *
 * Chains:
 * wrapped blob (ephemeral) -> TPKEY-wrapped blob -> ICE_SLAVE import + KDF.
 */
static TEE_Result program_content_key_using_hwkm(uint32_t pipe,
						 const uint8_t *wrapped_blob,
						 size_t wrapped_blob_len)
{
	uint8_t tpkey_blob[HWKM_MAX_BLOB_SIZE] = { };
	size_t tpkey_blob_len = sizeof(tpkey_blob);
	TEE_Result res = TEE_ERROR_GENERIC;

	res = export_tpkey_wrapped_blob_from_ephemeral(wrapped_blob,
						       wrapped_blob_len,
						       tpkey_blob,
						       &tpkey_blob_len);
	if (res != TEE_SUCCESS)
		goto out;

	res = program_ice_slave_from_tpkey_blob(pipe, tpkey_blob, tpkey_blob_len);

out:
	memset(tpkey_blob, 0, sizeof(tpkey_blob));
	return res;
}

/*
 * set_config_ice_key_using_hwkm() - Top-level HWKM + ICE register sequence.
 *
 * Sequence:
 * 1) Disable ICE slot configuration.
 * 2) Program key to mapped ICE slot through HWKM helper chain.
 * 3) Program fixed data-unit configuration.
 * 4) Enable ICE slot configuration.
 *
 * Fixed UFS settings:
 * - CAPIDX = AES-XTS-256
 * - DUSIZE = 4096-byte data unit for UFS
 *          =  512-byte data unit for eMMC
 */
TEE_Result set_config_ice_key_using_hwkm(uint32_t slot,
					 const uint8_t *wrapped_blob,
					 size_t wrapped_blob_len)
{
	const uint32_t cap_index = ICE_CIPHER_MODE_XTS_256;
	uint32_t data_unit_size = ICE_DATA_UNIT_SIZE_4096;
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = 0;

	if (!wrapped_blob || wrapped_blob_len != HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (slot >= ICE_MAX_KEY_IDX)
		return TEE_ERROR_BAD_PARAMETERS;

	base = (vaddr_t)phys_to_virt(ICE_LUT_KEYS, MEM_AREA_IO_SEC,
				     ICE_LUT_KEYS_SIZE);

	/* Disable slot first to prevent use of stale key/config. */
	io_write32_off_field(base, ICE_CRYPTOCFG_r_16_OFF(slot),
			     ICE_CRYPTOCFG_r_16_CFGE_BMSK,
			     0x0);

	res = program_content_key_using_hwkm(slot, wrapped_blob, wrapped_blob_len);
	if (res != TEE_SUCCESS)
		return res;

	/* Program fixed capability index (CAPIDX) and data unit size (DUSIZE). */
	io_write32_off_field(base, ICE_CRYPTOCFG_r_16_OFF(slot),
			     ICE_CRYPTOCFG_r_16_CAPIDX_BMSK,
			     cap_index);
	dsb();

	if (ICE_LUT_KEYS == PERIPH_SS_SDC1_SDCC_ICE_LUT_KEYS)
		data_unit_size = ICE_DATA_UNIT_SIZE_512;

	io_write32_off_field(base, ICE_CRYPTOCFG_r_16_OFF(slot),
			     ICE_CRYPTOCFG_r_16_DUSIZE_BMSK,
			     data_unit_size);
	dsb();

	/* Enable configuration (CFGE=1). */
	io_write32_off_field(base, ICE_CRYPTOCFG_r_16_OFF(slot),
			     ICE_CRYPTOCFG_r_16_CFGE_BMSK,
			     0x1);
	dsb();

	return TEE_SUCCESS;
}

/*
 * export_hw_wrapped_key() - Rewrap wrapped key blob under an ephemeral key.
 *
 * Sequence:
 * 1) Unwrap input blob with base wrapping key.
 * 2) Derive ephemeral wrapping key from RNG-provided context.
 * 3) Wrap key under ephemeral wrapping key.
 * 4) Clear ephemeral key slot.
 */
TEE_Result export_hw_wrapped_key(const uint8_t *in_blob, size_t in_blob_len,
				 uint8_t *out_blob, size_t *out_blob_len)
{
	const uint8_t *ephemeral_ctx = NULL;
	size_t ephemeral_ctx_len = 0;
	struct hwkm_transaction t_unwrap = {
		.cmd = {
			.op = HWKM_OP_KEY_UNWRAP_IMPORT,
			.unwrap = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.kwk = HWKM_SLOT_TZ_WRAP_KEY_SLOT,
			},
		},
	};
	struct hwkm_transaction t_wrap_ephemeral = {
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

	if (!in_blob || !out_blob || !out_blob_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_blob_len != HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*out_blob_len < HWKM_MAX_BLOB_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	res = get_or_init_ephemeral_ctx(&ephemeral_ctx, &ephemeral_ctx_len);
	if (res != TEE_SUCCESS)
		return res;

	mutex_lock(&drv->hwkm_lock);
	res = derive_l4_wrapping_key();
	if (res != TEE_SUCCESS)
		goto cleanup;

	memcpy(t_unwrap.cmd.unwrap.wkb, in_blob, HWKM_MAX_BLOB_SIZE);

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_unwrap);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_unwrap.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE export unwrap: unwrap=0x%x",
		     (unsigned int)t_unwrap.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	res = clear_l4_wrapping_key();
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = derive_ephemeral_wrapping_key(ephemeral_ctx, ephemeral_ctx_len);
	if (res != TEE_SUCCESS)
		goto cleanup;

	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_wrap_ephemeral);
	if (rc) {
		res = hwkm_to_optee(rc);
		goto cleanup;
	}

	if (t_wrap_ephemeral.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("ICE export rewrap: wrap=0x%x",
		     (unsigned int)t_wrap_ephemeral.rsp.status);
		res = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	memcpy(out_blob, t_wrap_ephemeral.rsp.wrap.wkb, HWKM_MAX_BLOB_SIZE);
	*out_blob_len = HWKM_MAX_BLOB_SIZE;
	res = TEE_SUCCESS;

cleanup:
	(void)clear_ephemeral_key();
	(void)clear_l4_wrapping_key();
	(void)hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear_gp1);
	mutex_unlock(&drv->hwkm_lock);

	memset(t_unwrap.cmd.unwrap.wkb, 0, sizeof(t_unwrap.cmd.unwrap.wkb));
	memset(t_wrap_ephemeral.rsp.wrap.wkb, 0, sizeof(t_wrap_ephemeral.rsp.wrap.wkb));
	return res;
}

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
