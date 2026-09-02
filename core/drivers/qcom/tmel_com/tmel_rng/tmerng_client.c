// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_support.h>
#include <atomic.h>

#include "tmerng_client.h"
#include "tmecom_client.h"
#include "tmemessages_uids.h"

#define RNG_POOL_BASE		(IMEM_BASE + 0x920UL)
#define RNG_POOL_SIZE		32U

/* IMEM entropy pool populated by U-Boot SPL, used when native IRQs are off */
register_phys_mem(MEM_AREA_IO_SEC, RNG_POOL_BASE & ~SMALL_PAGE_MASK,
		  SMALL_PAGE_SIZE);

static TEE_Result get_bootloader_rng_pool(void *buf, size_t len)
{
	static uint32_t offset;
	uint8_t *output = (uint8_t *)buf;
	uint8_t *rng_pool = NULL;
	size_t i = 0;

	if (len > RNG_POOL_SIZE)
		DMSG("Bootloader RNG pool request (%zu) exceeds size (%u)",
		     len, RNG_POOL_SIZE);

	rng_pool = (uint8_t *)phys_to_virt(RNG_POOL_BASE,
					   MEM_AREA_IO_SEC,
					   RNG_POOL_SIZE);
	if (!rng_pool) {
		EMSG("IMEM RNG pool not mapped (phys 0x%lx)",
		     (unsigned long)RNG_POOL_BASE);
		return TEE_ERROR_GENERIC;
	}

	for (i = 0; i < len; i++) {
		uint32_t idx = atomic_inc32(&offset);
		size_t src = (idx - 1) % RNG_POOL_SIZE;

		output[i] = rng_pool[src];
		/* Overwrite consumed entropy so it is not reused */
		rng_pool[src] = (uint8_t)(0xBEEFCAFEU >> ((src % 4) * 8));
	}

	return TEE_SUCCESS;
}

static TEE_Result tme_rng_get_data(void *buf, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tme_rng_get_msg msg = { };
	paddr_t rng_paddr = 0;
	void *rng_buf = NULL;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len > TME_RNG_MAX_LENGTH) {
		EMSG("Requested length %zu exceeds maximum %u",
		     len, TME_RNG_MAX_LENGTH);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rng_buf = tmecom_client_get_coherent_buf(len, &rng_paddr);
	if (!rng_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (rng_paddr > UINT32_MAX) {
		EMSG("RNG buffer paddr 0x%lx exceeds 32-bit range", rng_paddr);
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	msg.input.length = len;
	msg.output.rng_buf_pdata = (uint32_t)rng_paddr;
	msg.output.rng_buf_length = len;
	msg.output.rng_buf_length_used = 0;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmecom_client_send_message(TME_MSG_UID_HCS_RNG_GET,
					 TME_MSG_UID_HCS_RNG_GET_PARAM_ID,
					 true, TMECOM_DEFAULT_TIMEOUT,
					 &msg, sizeof(msg),
					 NULL, NULL, NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME RNG IPC failed: 0x%x", ret);
		goto cleanup;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS) {
		EMSG("TME RNG failed, status: 0x%x", msg.output.status);
		DMSG("Seq status: tme=0x%x seq=0x%x kp0=0x%x kp1=0x%x rsp=0x%x",
		     msg.output.seq_status.tme_error_status,
		     msg.output.seq_status.seq_error_status,
		     msg.output.seq_status.seq_kp_error_status0,
		     msg.output.seq_status.seq_kp_error_status1,
		     msg.output.seq_status.seq_rsp_status);
		goto cleanup;
	}

	if (msg.output.rng_buf_length_used != len) {
		EMSG("TME returned %u bytes, expected %zu",
		     msg.output.rng_buf_length_used, len);
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	memcpy(buf, rng_buf, len);

cleanup:
	tmecom_client_release_buf();
	return ret;
}

TEE_Result tme_hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t *output = (uint8_t *)buf;
	TEE_Result res = TEE_SUCCESS;
	size_t filled = 0;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (thread_get_exceptions() & THREAD_EXCP_NATIVE_INTR)
		return get_bootloader_rng_pool(buf, len);

	while (filled < len) {
		size_t chunk = MIN(len - filled, (size_t)TME_RNG_MAX_LENGTH);

		res = tme_rng_get_data(output + filled, chunk);
		if (res != TEE_SUCCESS)
			return res;

		filled += chunk;
	}

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return tme_hw_get_random_bytes(buf, len);
}
