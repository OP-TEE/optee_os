/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_PAS_H
#define PLATFORM_PAS_H

#include <resource_table.h>
#include <tee_api_types.h>
#include <types_ext.h>

TEE_Result pas_platform_mem_setup(uint32_t pas_id, uint32_t fw_size,
				  uint32_t fw_base_low, uint32_t fw_base_high);
TEE_Result pas_platform_get_resource_table(uint32_t pas_id,
					   struct resource_table *rt,
					   size_t *size);
TEE_Result pas_platform_set_remote_state(uint32_t pas_id, uint32_t state);
TEE_Result pas_platform_auth_and_reset(uint32_t pas_id);
TEE_Result pas_platform_is_supported(uint32_t pas_id);
TEE_Result pas_platform_capabilities(uint32_t pas_id);
TEE_Result pas_platform_init_image(uint32_t pas_id);
TEE_Result pas_platform_shutdown(uint32_t pas_id);

struct pas_fw_region {
	paddr_t base;
	uint32_t size;
};

struct pas_metadata {
	const uint8_t *data;
	size_t size;
};

struct pas_hash_table {
	const uint8_t *table;
	size_t len;
	uint32_t entry_size;
};

#ifdef CFG_QCOM_PAS_AUTH
TEE_Result pas_platform_verify_image(uint32_t pas_id,
				     const struct pas_fw_region *fw,
				     const struct pas_metadata *metadata,
				     const struct pas_hash_table *hash);
#else
static inline TEE_Result
pas_platform_verify_image(uint32_t pas_id __unused,
			  const struct pas_fw_region *fw __unused,
			  const struct pas_metadata *metadata __unused,
			  const struct pas_hash_table *hash __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_QCOM_PAS_AUTH */

#endif
