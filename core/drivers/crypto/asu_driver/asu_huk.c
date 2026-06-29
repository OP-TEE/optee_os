// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <crypto/crypto.h>
#include <drivers/amd/asu_client.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/spinlock.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_fs.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>

/* Secure State HW Root of Trust */
#define SSTATE_OFFSET_ASYNC		U(0x14C)
#define SSTATE_OFFSET_SYNC		U(0x150)
#define SSTATE_VAL_ASYNC		U(0xA5A5A5A5)
#define SSTATE_VAL_SYNC			U(0x96969696)

/* ASU module constants for HUK operations */
#define ASU_MODULE_ID_HUK		11U
#define ASU_CMD_ID_GET_HUK		6U
#define ASU_HUK_SIZE_IN_BYTES		32U
#define ASU_CMD_LEN_ZERO		0U

struct huk_context {
	uint8_t *huk_buf;
	bool callback_invoked;
};

/* Cached HUK state: fetched once from ASU firmware, protected by spinlock */
static struct {
	uint8_t data[ASU_HUK_SIZE_IN_BYTES];
	bool is_ready;
	bool fetch_in_progress;
	unsigned int lock;
} cached_huk = {
	.is_ready = false,
	.fetch_in_progress = false,
	.lock = SPINLOCK_UNLOCK,
};

/*
 * Callback handler for HUK response from ASU firmware.
 * Validates response and copies 32-byte HUK from firmware response buffer.
 */
static TEE_Result huk_response_handler(void *cbptr,
				       struct asu_resp_buf *resp)
{
	struct huk_context *ctx = (struct huk_context *)cbptr;

	if (!ctx || !ctx->huk_buf || !resp)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Copy 256-bit HUK from ASU response.
	 * arg[0] is the status word: to be ignored for HUK
	 * HUK data starts at arg[1].
	 */
	memcpy(ctx->huk_buf, (uint8_t *)&resp->arg[1], ASU_HUK_SIZE_IN_BYTES);
	ctx->callback_invoked = true;

	return TEE_SUCCESS;
}

/*
 * Request HUK from ASU firmware via IPI.
 * This is a BLOCKING operation - asu_update_queue_buffer_n_send_ipi()
 * guarantees the callback completes before returning. The unique_id
 * is only freed after the callback has been invoked.
 */
static TEE_Result asu_get_huk(uint8_t *huk_buf)
{
	struct asu_client_params params = { 0 };
	struct huk_context ctx = { 0 };
	uint32_t header = 0;
	uint32_t status = 0;
	uint8_t unique_id = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!huk_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx.huk_buf = huk_buf;
	ctx.callback_invoked = false;

	unique_id = asu_alloc_unique_id();
	if (unique_id >= ASU_UNIQUE_ID_MAX)
		return TEE_ERROR_BUSY;

	params.cbhandler = huk_response_handler;
	params.cbptr = &ctx;
	params.priority = ASU_PRIORITY_HIGH;

	header = asu_create_header(ASU_CMD_ID_GET_HUK, unique_id,
				   ASU_MODULE_ID_HUK, ASU_CMD_LEN_ZERO);

	/*
	 * Send IPI and block until ASU firmware responds.
	 * asu_update_queue_buffer_n_send_ipi() is SYNCHRONOUS - it blocks
	 * until the callback completes. Only after callback returns do we
	 * free the unique_id.
	 */
	ret = asu_update_queue_buffer_n_send_ipi(&params, NULL, 0U,
						 header, &status);

	asu_free_unique_id(unique_id);

	if (ret != TEE_SUCCESS) {
		EMSG("ASU IPI failed: 0x%x", ret);
		goto err;
	}

	if (status != 0) {
		EMSG("ASU firmware error: 0x%x", status);
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	if (!ctx.callback_invoked) {
		EMSG("ASU callback not invoked");
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	return TEE_SUCCESS;

err:
	memzero_explicit(huk_buf, ASU_HUK_SIZE_IN_BYTES);
	return ret;
}

/* Validate HUK is non-zero (all-zero indicates ASU firmware failure) */
static bool is_huk_valid(const uint8_t *huk)
{
	uint8_t accum = 0;
	size_t i = 0;

	if (!huk)
		return false;

	for (i = 0; i < ASU_HUK_SIZE_IN_BYTES; i++)
		accum |= huk[i];

	return accum != 0;
}

/*
 * Fetch HUK from ASU firmware and cache (thread-safe).
 * Uses fetch_in_progress flag to prevent TOCTOU race where multiple
 * threads could simultaneously issue IPI requests to ASU firmware.
 */
static TEE_Result asu_fetch_and_cache_huk(void)
{
	const uint32_t wait_retries = 500U; /* 500 * 10us = ~5ms max wait */
	uint8_t temp_huk[ASU_HUK_SIZE_IN_BYTES] = { 0 };
	uint32_t exceptions = 0;
	uint32_t retry = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	for (;;) {
		exceptions = cpu_spin_lock_xsave(&cached_huk.lock);

		/* Fast path: HUK already cached */
		if (cached_huk.is_ready) {
			cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);
			return TEE_SUCCESS;
		}

		/*
		 * Another thread is already fetching - wait for it to finish
		 * and re-evaluate. Fetch is synchronous so the wait should be
		 * short.
		 */
		if (cached_huk.fetch_in_progress) {
			cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);
			if (retry >= wait_retries)
				return TEE_ERROR_BUSY;
			udelay(10);
			retry++;
			continue;
		}

		/* This thread will perform the fetch */
		cached_huk.fetch_in_progress = true;
		cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);
		break;
	}

	/* Fetch into temporary buffer without holding lock (IPI blocks) */
	ret = asu_get_huk(temp_huk);
	if (ret != TEE_SUCCESS)
		goto err;

	/* Validate ASU firmware populated the HUK */
	if (!is_huk_valid(temp_huk)) {
		EMSG("ASU returned all-zero HUK");
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Atomically cache the validated HUK */
	exceptions = cpu_spin_lock_xsave(&cached_huk.lock);
	memcpy(cached_huk.data, temp_huk, sizeof(cached_huk.data));
	cached_huk.is_ready = true;
	cached_huk.fetch_in_progress = false;
	cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);

	memzero_explicit(temp_huk, sizeof(temp_huk));
	return TEE_SUCCESS;

err:
	/* Clear fetch_in_progress on error */
	exceptions = cpu_spin_lock_xsave(&cached_huk.lock);
	cached_huk.fetch_in_progress = false;
	cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);

	memzero_explicit(temp_huk, sizeof(temp_huk));
	return ret;
}

/*
 * Pre-fetch HUK during boot (after ASU driver init).
 * The HUK is used by multiple OP-TEE subsystems for secure storage,
 * TA encryption, and key derivation. Fetching early allows fail-fast
 * detection and avoids blocking cryptographic operations later.
 */
static TEE_Result asu_huk_init(void)
{
	TEE_Result ret = asu_fetch_and_cache_huk();

	if (ret == TEE_SUCCESS)
		DMSG("HUK cached from ASU firmware");
	else
		EMSG("HUK init failed: 0x%x", ret);

	return ret;
}

service_init_late(asu_huk_init);

#if defined(CFG_RPMB_FS)
/*
 * Gate for RPMB key provisioning, called by tee_rpmb_write_and_verify_key()
 * exactly once on first boot when the RPMB auth key has not yet been written
 * to the device. On subsequent boots the key is verified directly and this
 * function is never reached.
 *
 * Returns true only when both conditions hold:
 *	1. The HUK has been fetched and cached from ASU firmware
 *	(cached_huk.is_ready).
 *	2. The platform secure state register (PLAT_SST) reports an operational
 *	lifecycle state: async (0xA5A5A5A5) or sync (0x96969696).
 *
 * The hardware state check prevents key derivation and RPMB provisioning from
 * proceeding if the SoC lifecycle has not reached the expected stage, even if
 * the HUK cache is populated.
 */
bool plat_rpmb_key_is_ready(void)
{
	uint32_t exceptions = 0;
	uint32_t async_val = 0;
	uint32_t sync_val = 0;
	vaddr_t secstr = (vaddr_t)phys_to_virt(PLAT_SST_BASE,
						MEM_AREA_IO_SEC,
						PLAT_SST_LEN);
	if (!secstr) {
		EMSG("SST region not mapped");
		return false;
	}

	async_val = io_read32(secstr + SSTATE_OFFSET_ASYNC);
	sync_val  = io_read32(secstr + SSTATE_OFFSET_SYNC);

	exceptions = cpu_spin_lock_xsave(&cached_huk.lock);

	if (cached_huk.is_ready &&
	    (async_val == SSTATE_VAL_ASYNC ||
	     sync_val == SSTATE_VAL_SYNC)) {
		cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);
		return true;
	}

	cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);

	return false;
}
#endif

/*
 * Platform-specific HUK implementation required by OP-TEE core.
 * The HUK is derived into subkeys for secure storage, TA encryption,
 * and other cryptographic operations. Returns the cached HUK fetched
 * during boot initialization.
 *
 * Note: ASU provides 256-bit (32-byte) HUK but OP-TEE expects 128-bit
 * (16-byte) HUK. We derive via SHA-256(label || HUK) with a fixed
 * domain-separation label, and use the first 16 bytes of the digest.
 */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	static const uint8_t huk_label[] = "AMD-ASU-HUK";
	uint8_t hash[TEE_SHA256_HASH_SIZE] = { 0 };
	uint8_t huk[ASU_HUK_SIZE_IN_BYTES] = { 0 };
	uint32_t exceptions = 0;
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	COMPILE_TIME_ASSERT(HW_UNIQUE_KEY_LENGTH <= TEE_SHA256_HASH_SIZE);

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&cached_huk.lock);

	if (!cached_huk.is_ready) {
		cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);
		EMSG("HUK not ready - initialization incomplete");
		return TEE_ERROR_BAD_STATE;
	}

	memcpy(huk, cached_huk.data, sizeof(huk));
	cpu_spin_unlock_xrestore(&cached_huk.lock, exceptions);

	/*
	 * Derive 16-byte OP-TEE HUK from 32-byte ASU HUK using SHA-256.
	 * This preserves all 256 bits of entropy from ASU firmware.
	 */
	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		goto out_zero;

	res = crypto_hash_init(ctx);
	if (res)
		goto out_zero;

	/* Add domain-separation label before hashing raw HUK */
	res = crypto_hash_update(ctx, huk_label, sizeof(huk_label) - 1U);
	if (res)
		goto out_zero;

	res = crypto_hash_update(ctx, huk, ASU_HUK_SIZE_IN_BYTES);
	if (res)
		goto out_zero;

	res = crypto_hash_final(ctx, hash, sizeof(hash));
	if (res)
		goto out_zero;

	/* Use first 16 bytes of SHA-256 hash as OP-TEE HUK */
	memcpy(hwkey->data, hash, HW_UNIQUE_KEY_LENGTH);

out_zero:
	crypto_hash_free_ctx(ctx);
	memzero_explicit(hash, sizeof(hash));
	memzero_explicit(huk, sizeof(huk));

	if (res != TEE_SUCCESS)
		EMSG("Failed to derive HUK: 0x%x", res);

	return res;
}
