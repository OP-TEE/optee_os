// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <tmel_com_client.h>
#include <tmel_km_client.h>
#include <tmel_messages_uids.h>
#include <trace.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_FUSE_PRI_HW_KEY_BASE_START,
			SMALL_PAGE_SIZE);

TEE_Result tmel_km_derive_key(const struct tme_kdf_spec *kdf_spec,
			      uint32_t *key_handle)
{
	struct tmel_com_data data = { .in = kdf_spec,
				      .in_len = sizeof(*kdf_spec) };
	struct tmel_km_derive_key_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!kdf_spec || !key_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.input.key_id = TME_KEY_HANDLE_ALLOC;
	msg.input.kdf_info = tmel_com_client_data_pa();
	msg.input.kdf_info_len = sizeof(*kdf_spec);
	msg.input.cred_slot = TME_CRED_SLOT_ID_NONE;
	msg.output.status = TME_STATUS_UNKNOWN;
	msg.output.key_id = TME_KEY_HANDLE_INVALID;

	ret = tmel_com_client_send_message(TME_MSG_UID_KM_DERIVE,
					   TMEL_COM_DEFAULT_TIMEOUT,
					   &msg, sizeof(msg), &data);
	if (ret != TEE_SUCCESS) {
		EMSG("TME derive key IPC failed: %#" PRIx32, ret);
		return ret;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS) {
		EMSG("TME derive key failed, status: %#" PRIx32,
		     msg.output.status);
		return ret;
	}

	*key_handle = msg.output.key_id;

	return TEE_SUCCESS;
}

TEE_Result tmel_km_distribute_key(uint32_t key_handle,
				  uint32_t dst_id,
				  uint32_t dst_idx)
{
	struct tmel_km_distribute_key_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (key_handle == TME_KEY_HANDLE_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.input.key_id = key_handle;
	msg.input.dst_id = dst_id;
	msg.input.dst_idx = dst_idx;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmel_com_client_send_message(TME_MSG_UID_KM_DISTRIBUTE,
					   TMEL_COM_DEFAULT_TIMEOUT,
					   &msg, sizeof(msg), NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME distribute key IPC failed: %#" PRIx32, ret);
		return ret;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS)
		EMSG("TME distribute key failed, status: %#" PRIx32,
		     msg.output.status);

	return ret;
}

TEE_Result tmel_km_clear_key(uint32_t key_handle)
{
	struct tmel_km_clear_key_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (key_handle == TME_KEY_HANDLE_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.input.key_id = key_handle;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmel_com_client_send_message(TME_MSG_UID_KM_CLEAR,
					   TMEL_COM_DEFAULT_TIMEOUT,
					   &msg, sizeof(msg), NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME clear key IPC failed: %#" PRIx32, ret);
		return ret;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS)
		EMSG("TME clear key failed, status: %#" PRIx32,
		     msg.output.status);

	return ret;
}

TEE_Result tmel_km_create_key_policy(uint32_t key_length,
				     uint32_t algo_mode,
				     uint32_t key_destination,
				     uint32_t lineage,
				     struct tme_key_policy *policy)
{
	if (!policy)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_length != 128 && key_length != 256) {
		EMSG("Invalid key length: %u (must be 128 or 256)", key_length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	policy->low = TME_KT_SYMMETRIC | TME_KP_GENERIC |
		      TME_KOP_ENCRYPTION | TME_KOP_DECRYPTION |
		      TME_KSL_HW_KEY | TME_KO_TZ | lineage;
	policy->low |= (key_length == 128) ? TME_KL_128 : TME_KL_256;
	policy->low |= algo_mode;

	policy->high = TME_KPV_VERSION | TME_KAU_TZ;
	if (key_destination == TME_KD_ICE_ENDPOINT)
		policy->high |= TME_KD_ICE_ENDPOINT;
	else if (key_destination == TME_KD_TCSR_ENDPOINT)
		policy->high |= TME_KD_TCSR_ENDPOINT;

	return TEE_SUCCESS;
}

TEE_Result tmel_km_read_tcsr_key_and_clear(uint32_t *key, uint32_t key_size,
					   uint32_t slot_id)
{
	paddr_t tcsr_pa = 0;
	vaddr_t tcsr = 0;
	uint32_t reg_count = 0;
	size_t total_size = 0;
	uint32_t i = 0;

	if (!key || slot_id > 1)
		return TEE_ERROR_BAD_PARAMETERS;

	if (slot_id == 0) {
		tcsr_pa = TCSR_FUSE_PRI_HW_KEY_BASE_START;
		reg_count = TCSR_FUSE_PRI_HW_KEY_REG_COUNT;
	} else {
		tcsr_pa = TCSR_FUSE_SEC_HW_KEY_BASE_START;
		reg_count = TCSR_FUSE_SEC_HW_KEY_REG_COUNT;
	}

	total_size = reg_count * sizeof(uint32_t);
	if (key_size < total_size)
		return TEE_ERROR_SHORT_BUFFER;

	tcsr = core_mmu_get_va(tcsr_pa, MEM_AREA_IO_SEC, total_size);
	if (!tcsr)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < reg_count; i++)
		key[i] = io_read32(tcsr + i * sizeof(uint32_t));

	for (i = 0; i < reg_count; i++)
		io_write32(tcsr + i * sizeof(uint32_t), 0);

	dsb();

	for (i = 0; i < reg_count; i++) {
		if (io_read32(tcsr + i * sizeof(uint32_t)) != 0) {
			EMSG("Failed to clear TCSR register %u", i);
			memset(key, 0, total_size);
			return TEE_ERROR_SECURITY;
		}
	}

	return TEE_SUCCESS;
}
