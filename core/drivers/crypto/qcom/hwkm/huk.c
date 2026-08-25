// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#include <config.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <string.h>
#include <trace.h>

#include <hwkm.h>
#include <hwkm_errno.h>

#define HWKM_HUK_MKS_CTX	"OPTEE_HUK_HWKM_V1_MKS"
#define HWKM_HUK_L3_CTX		"OPTEE_HUK_HWKM_V1_L3"
#define HWKM_HUK_L4_CTX		"OPTEE_HUK_HWKM_V1_L4"

#define HWKM_SCRATCH_SLOT_MKS	HWKM_SLOT_TZ_MIXING_KEY_SLOT
#define HWKM_SCRATCH_SLOT_A	HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1
#define HWKM_SCRATCH_SLOT_B	HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT2

static void hwkm_setup_kdf(struct hwkm_transaction *t,
			   uint8_t dks, uint8_t kdk, uint8_t mks,
			   const struct hwkm_key_policy *policy,
			   const struct hwkm_bsve *bsve,
			   const char *ctx, size_t ctx_len)
{
	t->cmd.op = HWKM_OP_SYSTEM_KDF;
	t->cmd.kdf.dks = dks;
	t->cmd.kdf.kdk = kdk;
	t->cmd.kdf.mks = mks;
	t->cmd.kdf.policy = *policy;
	t->cmd.kdf.bsve = *bsve;
	t->cmd.kdf.ctx_len = ctx_len;
	memcpy(t->cmd.kdf.ctx, ctx, ctx_len);
}

/*
 * hwkm_huk_derive_mks() - Derive the SKDK L3 mixing key into the MKS slot.
 *
 * TZ_SKDK_L2 is an L2 static key and cannot be used directly as the MKS
 * argument in SYSTEM_KDF (hardware rejects L1/L2 slots with
 * HWKM_SYSTEM_KDF_ERR_MKS_L1L2_NOT_ALLOWED). This function produces a stable
 * L3 generic key from TZ_SKDK_L2 and loads it into HWKM_SCRATCH_SLOT_MKS.
 *
 * Return: TEE_SUCCESS on success, or a TEE_ERROR_* code on failure.
 */
static TEE_Result hwkm_huk_derive_mks(void)
{
	/* SKDK L3 mixing key: kdf_depth = 0 so it cannot be used as a KDK. */
	const struct hwkm_key_policy mks_policy = {
		.km_by_tz_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_CMAC,
		.enc_allowed = true,
		.dec_allowed = true,
		.key_type = HWKM_KEY_TYPE_GENERIC_KEY,
		.security_lvl = HWKM_KEY_SECURITY_LVL_SW_KEY,
		.hw_destination = HWKM_KEY_DEST_KM_MASTER,
	};
	const struct hwkm_bsve mks_bsve = {
		.enabled = true,
		.km_swc_en = true,
		.km_apps_secure_en = true,
		.km_fuse_region_sha_digest_en =
			UINT64_C(CFG_HWKM_HUK_FUSE_REGION_DIGEST),
	};
	struct hwkm_transaction *t_clear = NULL;
	struct hwkm_transaction *t_kdf = NULL;
	TEE_Result res = TEE_SUCCESS;
	int rc = 0;

	t_clear = hwkm_transaction_alloc();
	t_kdf = hwkm_transaction_alloc();
	if (!t_clear || !t_kdf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	t_clear->cmd.op = HWKM_OP_KEY_SLOT_CLEAR;
	t_clear->cmd.clear.dks = HWKM_SCRATCH_SLOT_MKS;
	t_clear->cmd.clear.is_double_key = false;
	hwkm_setup_kdf(t_kdf, HWKM_SCRATCH_SLOT_MKS, HWKM_SLOT_TZ_SKDK_L2,
		       0, &mks_policy, &mks_bsve,
		       HWKM_HUK_MKS_CTX, sizeof(HWKM_HUK_MKS_CTX) - 1);

	rc = hwkm_run_transactions(HWKM_KEY_DEST_KM_MASTER, 2,
				   (struct hwkm_transaction *const[]){
					t_clear, t_kdf });
	if (rc) {
		res = hwkm_to_optee(rc);
		goto out_clear;
	}

	if (t_clear->rsp.status != HWKM_RSP_ERR_SUCCESS &&
	    t_clear->rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) {
		res = TEE_ERROR_GENERIC;
		goto out_clear;
	}

	if (t_kdf->rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: SYSTEM_KDF MKS failed: %s",
		     hwkm_err2str(t_kdf->rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out_clear;
	}

	goto out;

out_clear:
	/* Ensure the MKS slot is clean before surfacing the error. */
	t_clear->hdl = NULL;
	hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, t_clear);

out:
	hwkm_transaction_free(t_clear);
	hwkm_transaction_free(t_kdf);
	return res;
}

/*
 * hwkm_huk_derive_keys() - Run the two-level UKDK KDF and read out the HUK.
 * @huk: Output buffer receiving the derived hardware unique key.
 *
 * Derives the UKDK L3 KDK into HWKM_SCRATCH_SLOT_A with the SKDK L3 mixing
 * key in HWKM_SCRATCH_SLOT_MKS bound via BSVE.MKS_EN, then derives the final
 * L4 HUK from slot A into slot B, reads it out, and clears all three scratch
 * slots.
 *
 * Return: TEE_SUCCESS on success, or a TEE_ERROR_* code on failure.
 *         All three scratch slots are cleared on any failure before returning.
 */
static TEE_Result hwkm_huk_derive_keys(uint8_t huk[HW_UNIQUE_KEY_LENGTH])
{
	/* L3: intermediate KDK derived from TZ_UKDK_L2. */
	const struct hwkm_key_policy l3_policy = {
		.km_by_tz_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_CMAC,
		.enc_allowed = true,
		.dec_allowed = true,
		.key_type = HWKM_KEY_TYPE_KDK,
		.kdf_depth = 1,
		.security_lvl = HWKM_KEY_SECURITY_LVL_HW_KEY,
		.hw_destination = HWKM_KEY_DEST_KM_MASTER,
	};
	/* L4: final SW-readable HUK derived from the L3 KDK. */
	const struct hwkm_key_policy l4_policy = {
		.km_by_tz_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_CMAC,
		.enc_allowed = true,
		.dec_allowed = true,
		.key_type = HWKM_KEY_TYPE_GENERIC_KEY,
		.security_lvl = HWKM_KEY_SECURITY_LVL_SW_KEY,
		.hw_destination = HWKM_KEY_DEST_KM_MASTER,
	};
	const struct hwkm_bsve huk_bsve = {
		.enabled = true,
		.km_swc_en = true,
		.km_apps_secure_en = true,
		.km_mks_en = IS_ENABLED(CFG_HWKM_HUK_MIX_SKDK),
		.km_fuse_region_sha_digest_en =
			UINT64_C(CFG_HWKM_HUK_FUSE_REGION_DIGEST),
	};
	struct hwkm_transaction *t_clear_a = NULL;
	struct hwkm_transaction *t_clear_b = NULL;
	struct hwkm_transaction *t_clear_mks = NULL;
	struct hwkm_transaction *t_kdf_l3 = NULL;
	struct hwkm_transaction *t_kdf_l4 = NULL;
	struct hwkm_transaction *t_read = NULL;
	TEE_Result res = TEE_SUCCESS;
	int rc = 0;

	t_clear_a = hwkm_transaction_alloc();
	t_clear_b = hwkm_transaction_alloc();
	t_clear_mks = hwkm_transaction_alloc();
	t_kdf_l3 = hwkm_transaction_alloc();
	t_kdf_l4 = hwkm_transaction_alloc();
	t_read = hwkm_transaction_alloc();
	if (!t_clear_a || !t_clear_b || !t_clear_mks ||
	    !t_kdf_l3 || !t_kdf_l4 || !t_read) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	t_clear_a->cmd.op = HWKM_OP_KEY_SLOT_CLEAR;
	t_clear_a->cmd.clear.dks = HWKM_SCRATCH_SLOT_A;
	t_clear_a->cmd.clear.is_double_key = false;
	t_clear_b->cmd.op = HWKM_OP_KEY_SLOT_CLEAR;
	t_clear_b->cmd.clear.dks = HWKM_SCRATCH_SLOT_B;
	t_clear_b->cmd.clear.is_double_key = false;
	t_clear_mks->cmd.op = HWKM_OP_KEY_SLOT_CLEAR;
	t_clear_mks->cmd.clear.dks = HWKM_SCRATCH_SLOT_MKS;
	t_clear_mks->cmd.clear.is_double_key = false;
	hwkm_setup_kdf(t_kdf_l3, HWKM_SCRATCH_SLOT_A, HWKM_SLOT_TZ_UKDK_L2,
		       HWKM_SCRATCH_SLOT_MKS, &l3_policy, &huk_bsve,
		       HWKM_HUK_L3_CTX, sizeof(HWKM_HUK_L3_CTX) - 1);
	hwkm_setup_kdf(t_kdf_l4, HWKM_SCRATCH_SLOT_B, HWKM_SCRATCH_SLOT_A,
		       HWKM_SCRATCH_SLOT_MKS, &l4_policy, &huk_bsve,
		       HWKM_HUK_L4_CTX, sizeof(HWKM_HUK_L4_CTX) - 1);

	/* Clear A and B, derive UKDK L3 into A, derive L4 HUK into B. */
	rc = hwkm_run_transactions(HWKM_KEY_DEST_KM_MASTER, 4,
				   (struct hwkm_transaction *const[]){
					t_clear_a, t_clear_b,
					t_kdf_l3, t_kdf_l4 });
	if (rc) {
		res = hwkm_to_optee(rc);
		goto out_clear;
	}

	if ((t_clear_a->rsp.status != HWKM_RSP_ERR_SUCCESS &&
	     t_clear_a->rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) ||
	    (t_clear_b->rsp.status != HWKM_RSP_ERR_SUCCESS &&
	     t_clear_b->rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY)) {
		res = TEE_ERROR_GENERIC;
		goto out_clear;
	}

	if (t_kdf_l3->rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: SYSTEM_KDF L3 failed: %s",
		     hwkm_err2str(t_kdf_l3->rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out_clear;
	}

	if (t_kdf_l4->rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: SYSTEM_KDF L4 failed: %s",
		     hwkm_err2str(t_kdf_l4->rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out_clear;
	}

	/* Read L4 HUK from slot B, then clear A, B and MKS. */
	t_read->cmd.op = HWKM_OP_KEY_SLOT_RDWR;
	t_read->cmd.rdwr.slot = HWKM_SCRATCH_SLOT_B;
	t_read->cmd.rdwr.is_write = false;

	rc = hwkm_run_transactions(HWKM_KEY_DEST_KM_MASTER, 4,
				   (struct hwkm_transaction *const[]){
					t_read, t_clear_a,
					t_clear_b, t_clear_mks });
	if (rc) {
		res = hwkm_to_optee(rc);
		goto out_clear;
	}

	if (t_read->rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: KEY_SLOT_RDWR read failed: %s",
		     hwkm_err2str(t_read->rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out_clear;
	}

	if (t_clear_a->rsp.status != HWKM_RSP_ERR_SUCCESS ||
	    t_clear_b->rsp.status != HWKM_RSP_ERR_SUCCESS ||
	    t_clear_mks->rsp.status != HWKM_RSP_ERR_SUCCESS) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(huk, t_read->rsp.rdwr.key, HW_UNIQUE_KEY_LENGTH);
	goto out;

out_clear:
	t_clear_a->hdl = NULL;
	t_clear_b->hdl = NULL;
	t_clear_mks->hdl = NULL;
	hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, t_clear_a);
	hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, t_clear_b);
	hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, t_clear_mks);

out:
	hwkm_transaction_free(t_clear_a);
	hwkm_transaction_free(t_clear_b);
	hwkm_transaction_free(t_clear_mks);
	hwkm_transaction_free(t_kdf_l3);
	hwkm_transaction_free(t_kdf_l4);
	hwkm_transaction_free(t_read);
	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	struct hwkm_drv_ctx *drv = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	drv = hwkm_get_context();
	if (!drv)
		return TEE_ERROR_NOT_SUPPORTED;

	mutex_lock(&drv->hwkm_lock);

	if (drv->hwkm_huk_ready) {
		memcpy(hwkey->data, drv->hwkm_huk, HW_UNIQUE_KEY_LENGTH);
		goto out;
	}

	if (IS_ENABLED(CFG_HWKM_HUK_MIX_SKDK)) {
		res = hwkm_huk_derive_mks();
		if (res)
			goto out;
	}

	res = hwkm_huk_derive_keys(drv->hwkm_huk);
	if (res)
		goto out;

	drv->hwkm_huk_ready = true;
	memcpy(hwkey->data, drv->hwkm_huk, HW_UNIQUE_KEY_LENGTH);

out:
	mutex_unlock(&drv->hwkm_lock);
	return res;
}
