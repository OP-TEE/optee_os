// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 * ASU TRNG Driver for OP-TEE
 * Provides True Random Number Generator functionality via ASU firmware
 */

#include <crypto/crypto.h>
#include <drivers/amd/asu_client.h>
#include <kernel/panic.h>
#include <rng_support.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#define ASU_TRNG_BYTES_PER_REQUEST	32U /* Bytes per request */
#define ASU_TRNG_OPERATION_CMD_ID	0U  /* ASU command ID */

/* TRNG callback context */
struct asu_trng_cbctx {
	uint8_t *output;
	size_t copy_size;
};

/**
 * asu_trng_cb() - TRNG response callback
 * @cbrefptr: Callback context pointer
 * @resp_buf: ASU response buffer containing random data
 *
 * Return: TEE_SUCCESS on success, error code on failure
 */
static TEE_Result asu_trng_cb(void *cbrefptr, struct asu_resp_buf *resp_buf)
{
	struct asu_trng_cbctx *cbctx = NULL;
	const uint8_t *src_addr = NULL;

	if (!cbrefptr || !resp_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	cbctx = (struct asu_trng_cbctx *)cbrefptr;
	src_addr = (const uint8_t *)
		    &resp_buf->arg[ASU_RESPONSE_BUFF_ADDR_INDEX];

	/* Copy the requested bytes from response */
	memcpy(cbctx->output, src_addr, cbctx->copy_size);

	return TEE_SUCCESS;
}

/**
 * asu_trng_op() - Send TRNG request to ASU firmware
 * @cbctx: Callback context with output buffer info
 * @uniqueid: Unique request identifier
 *
 * Return: TEE_SUCCESS on success, error code on failure
 */
static TEE_Result asu_trng_op(struct asu_trng_cbctx *cbctx, uint8_t uniqueid)
{
	struct asu_client_params cparam = {};
	uint32_t header = 0;
	uint32_t status = 0;
	TEE_Result ret = TEE_SUCCESS;

	/* Setup client parameters with callback to receive random data */
	cparam.priority = ASU_PRIORITY_HIGH;
	cparam.cbhandler = asu_trng_cb;  /* Callback to receive response */
	cparam.cbptr = cbctx;

	/* Create request header - no payload needed */
	header = asu_create_header(ASU_TRNG_OPERATION_CMD_ID,
				   uniqueid,
				   ASU_MODULE_TRNG_ID,
				   0U);  /* Length = 0, no command payload */

	ret = asu_update_queue_buffer_n_send_ipi(&cparam, NULL,
						 0, header,
						 &status);

	if (ret != TEE_SUCCESS) {
		EMSG("ASU queue operation failed: ret=0x%x", ret);
		return ret;
	}

	if (status != 0) {
		EMSG("ASU FW TRNG error: status=0x%x", status);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/**
 * hw_get_random_bytes() - Get random bytes from ASU TRNG
 * @buf: Output buffer for random data
 * @len: Number of bytes requested
 *
 * Return: TEE_SUCCESS on success, error code on failure
 */
TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	struct asu_trng_cbctx cbctx = {};
	uint8_t uniqueid = ASU_UNIQUE_ID_MAX;
	uint8_t *output = (uint8_t *)buf;
	size_t remaining = len;
	TEE_Result ret = TEE_SUCCESS;

	/* Validate input parameters */
	if (!buf || len == 0U) {
		EMSG("Invalid parameters: buf=%p, len=%zu", buf, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Allocate unique request ID */
	uniqueid = asu_alloc_unique_id();
	if (uniqueid == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to allocate unique ID");
		return TEE_ERROR_GENERIC;
	}

	while (remaining > 0U) {
		/* Calculate bytes to request (up to 32 bytes) */
		cbctx.copy_size = MIN(remaining, ASU_TRNG_BYTES_PER_REQUEST);
		cbctx.output = output;

		/* Send request to ASU firmware and receive data via callback */
		ret = asu_trng_op(&cbctx, uniqueid);
		if (ret != TEE_SUCCESS) {
			EMSG("TRNG operation failed");
			break;
		}

		/* Update buffer pointer and remaining length */
		output += cbctx.copy_size;
		remaining -= cbctx.copy_size;
	}

	/* Free unique request ID */
	asu_free_unique_id(uniqueid);

	return ret;
}

#ifdef CFG_WITH_SOFTWARE_PRNG
/**
 * plat_rng_init() - Seed PRNG with hardware entropy
 *
 * Called by crypto subsystem at service_init_crypto. Seeds Fortuna PRNG
 * with 64 bytes of hardware random data from ASU TRNG.
 */
void plat_rng_init(void)
{
	uint8_t seed[64] = { };
	TEE_Result res = TEE_SUCCESS;

	IMSG("Seeding Fortuna PRNG with ASU TRNG hardware entropy");

	/* Get 64 bytes of true random data from ASU TRNG */
	res = hw_get_random_bytes(seed, sizeof(seed));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get random bytes from ASU TRNG: %#"PRIx32,
		     res);
		panic("Cannot seed PRNG without hardware entropy");
	}

	/* Seed the Fortuna PRNG with hardware entropy */
	res = crypto_rng_init(seed, sizeof(seed));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to seed Fortuna PRNG: %#" PRIx32, res);
		panic("PRNG seeding failed");
	}

	IMSG("Fortuna PRNG successfully seeded with 64 bytes from ASU TRNG");
}
#endif /* CFG_WITH_SOFTWARE_PRNG */
