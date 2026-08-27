// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_FUSE_PRI_HW_KEY_BASE_START,
			SMALL_PAGE_SIZE);

#include "tmekm_client.h"
#include "tmecom_client.h"
#include "tmemessages_uids.h"

TEE_Result tme_km_derive_key(const struct tme_kdf_spec *kdf_spec,
			     uint32_t *key_handle)
{
	struct tme_km_derive_key_msg msg = { };
	struct tme_kdf_spec *kdf_buf = NULL;
	size_t kdf_size = sizeof(*kdf_buf);
	TEE_Result ret = TEE_ERROR_GENERIC;
	paddr_t kdf_paddr = 0;

	if (!kdf_spec || !key_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	kdf_buf = tmecom_client_get_coherent_buf(kdf_size, &kdf_paddr);
	if (!kdf_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (kdf_paddr > UINT32_MAX) {
		EMSG("KDF buffer paddr 0x%lx exceeds 32-bit range", kdf_paddr);
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	memcpy(kdf_buf, kdf_spec, kdf_size);

	msg.input.key_id = TME_KEY_HANDLE_ALLOC;
	msg.input.kdf_info_pdata = (uint32_t)kdf_paddr;
	msg.input.kdf_info_length = kdf_size;
	msg.input.cred_slot = TME_CRED_SLOT_ID_NONE;
	msg.output.status = TME_STATUS_UNKNOWN;
	msg.output.key_id = TME_KEY_HANDLE_INVALID;

	ret = tmecom_client_send_message(TME_MSG_UID_KM_DERIVE,
					 TME_MSG_UID_KM_DERIVE_PARAM_ID,
					 true, TMECOM_DEFAULT_TIMEOUT,
					 &msg, sizeof(msg),
					 NULL, NULL, NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME derive key IPC failed: 0x%x", ret);
		goto cleanup;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS) {
		EMSG("TME derive key failed, status: 0x%x", msg.output.status);
		goto cleanup;
	}

	*key_handle = msg.output.key_id;

cleanup:
	tmecom_client_release_buf();
	return ret;
}

TEE_Result tme_km_distribute_key(uint32_t key_handle,
				 uint32_t dst_id,
				 uint32_t dst_key_index)
{
	struct tme_km_distribute_key_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (key_handle == TME_KEY_HANDLE_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.input.key_id = key_handle;
	msg.input.dst_id = dst_id;
	msg.input.dst_key_index = dst_key_index;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmecom_client_send_message(TME_MSG_UID_KM_DISTRIBUTE,
					 TME_MSG_UID_KM_DISTRIBUTE_PARAM_ID,
					 true, TMECOM_DEFAULT_TIMEOUT,
					 &msg, sizeof(msg),
					 NULL, NULL, NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME distribute key IPC failed: 0x%x", ret);
		return ret;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS)
		EMSG("TME distribute key failed, status: 0x%x",
		     msg.output.status);

	return ret;
}

TEE_Result tme_km_clear_key(uint32_t key_handle)
{
	struct tme_km_clear_key_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (key_handle == TME_KEY_HANDLE_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.input.key_id = key_handle;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmecom_client_send_message(TME_MSG_UID_KM_CLEAR,
					 TME_MSG_UID_KM_CLEAR_PARAM_ID,
					 true, TMECOM_DEFAULT_TIMEOUT,
					 &msg, sizeof(msg),
					 NULL, NULL, NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME clear key IPC failed: 0x%x", ret);
		return ret;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS)
		EMSG("TME clear key failed, status: 0x%x", msg.output.status);

	return ret;
}

void tme_km_create_key_policy(uint32_t key_length,
			      uint32_t algo_mode,
			      uint32_t key_destination,
			      uint32_t lineage,
			      struct tme_key_policy *policy)
{
	uint32_t lo = 0;
	uint32_t hi = 0;

	if (!policy)
		return;

	if (key_length != 128 && key_length != 256) {
		EMSG("Invalid key length: %u (must be 128 or 256)", key_length);
		return;
	}

	lo = TME_KT_Symmetric | TME_KP_Generic |
	     TME_KOP_Encryption | TME_KOP_Decryption |
	     TME_KSL_HWKey | TME_KO_TZ | lineage;
	lo |= (key_length == 128) ? TME_KL_128 : TME_KL_256;
	lo |= algo_mode;

	hi = TME_KPV_Version | TME_KAU_TZ;
	if (key_destination == TME_KD_ICE_ENDPOINT)
		hi |= TME_KD_ICE_ENDPOINT;
	else if (key_destination == TME_KD_TCSR_ENDPOINT)
		hi |= TME_KD_TCSR_ENDPOINT;

	policy->low = lo;
	policy->high = hi;
}

TEE_Result tme_km_read_tcsr_key_and_clear(uint32_t *key, uint32_t key_size,
					  uint32_t slot_id)
{
	struct io_pa_va tcsr_pa_va = { };
	uint32_t *tcsr_addr = NULL;
	uint32_t reg_count = 0;
	size_t total_size = 0;
	uint32_t i = 0;

	if (!key || slot_id > 1)
		return TEE_ERROR_BAD_PARAMETERS;

	if (slot_id == 0) {
		tcsr_pa_va.pa = TCSR_FUSE_PRI_HW_KEY_BASE_START;
		reg_count = TCSR_FUSE_PRI_HW_KEY_REG_COUNT;
	} else {
		tcsr_pa_va.pa = TCSR_FUSE_SEC_HW_KEY_BASE_START;
		reg_count = TCSR_FUSE_SEC_HW_KEY_REG_COUNT;
	}

	total_size = reg_count * sizeof(uint32_t);
	if (key_size < total_size)
		return TEE_ERROR_SHORT_BUFFER;

	tcsr_addr = (uint32_t *)io_pa_or_va(&tcsr_pa_va, total_size);
	if (!tcsr_addr)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < reg_count; i++)
		key[i] = io_read32((vaddr_t)&tcsr_addr[i]);

	for (i = 0; i < reg_count; i++)
		io_write32((vaddr_t)&tcsr_addr[i], 0);

	dsb();
	isb();

	for (i = 0; i < reg_count; i++) {
		if (io_read32((vaddr_t)&tcsr_addr[i]) != 0) {
			EMSG("Failed to clear TCSR register %u", i);
			memset(key, 0, total_size);
			return TEE_ERROR_SECURITY;
		}
	}

	return TEE_SUCCESS;
}
