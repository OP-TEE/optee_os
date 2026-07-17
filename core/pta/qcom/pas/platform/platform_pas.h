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

/*
 * Verify the integrity of a loaded firmware image against an authenticated
 * per-segment hash table. Maps the firmware carveout, recomputes each segment
 * digest and compares it to the table, then unmaps. The hash table must have
 * already been authenticated (signature-verified) by the caller.
 *
 * When CFG_QCOM_PAS_AUTH is disabled this resolves to an inline stub that
 * returns TEE_ERROR_NOT_SUPPORTED, so callers (e.g. the PAS PTA's
 * VERIFY_IMAGE dispatch) stay free of build-config conditionals and the
 * authentication core (pas_auth_core.c) is not linked in.
 *
 * @pas_id:		remote processor identifier
 * @fw_size:		firmware carveout size in bytes (from AUTH_AND_RESET)
 * @fw_base:		firmware carveout physical base address
 * @metadata:		ELF metadata blob (header + phdrs); used for ELF
 *			parsing and ELF header hash (entry 0); NOT in carveout
 * @metadata_size:	size of @metadata in bytes
 * @hash_table:		authenticated digest table, one entry per program header
 * @table_len:		size of @hash_table in bytes
 * @hash_size:		digest size in bytes (32 for SHA-256, 48 for SHA-384)
 */
#ifdef CFG_QCOM_PAS_AUTH
TEE_Result pas_platform_verify_image(uint32_t pas_id, uint32_t fw_size,
				     paddr_t fw_base, const uint8_t *metadata,
				     size_t metadata_size,
				     const uint8_t *hash_table,
				     size_t table_len, uint32_t hash_size);
#else
static inline TEE_Result
pas_platform_verify_image(uint32_t pas_id __unused,
			  uint32_t fw_size __unused,
			  paddr_t fw_base __unused,
			  const uint8_t *metadata __unused,
			  size_t metadata_size __unused,
			  const uint8_t *hash_table __unused,
			  size_t table_len __unused,
			  uint32_t hash_size __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_QCOM_PAS_AUTH */

#endif
