/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_PAS_H
#define PLATFORM_PAS_H

#include <resource_table.h>

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

#endif
