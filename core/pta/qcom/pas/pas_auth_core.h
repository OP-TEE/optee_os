/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_AUTH_CORE_H
#define __PAS_AUTH_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* Maximum digest size handled (SHA-384). */
#define PAS_AUTH_CORE_MAX_HASH_SIZE	48U

/*
 * struct pas_auth_core_ctx - per-segment hash verification context
 * @hash_algo:      TEE_ALG_SHA256 or TEE_ALG_SHA384
 * @hash_size:      digest size in bytes (32 or 48)
 * @hash_table:     authenticated digest table, one entry per program header
 * @num_entries:    number of digests; must equal e_phnum
 * @metadata:       raw MBN metadata blob: ELF header + phdrs + hash segment;
 *                  used for ELF parsing and entry-0 hash (NOT loaded into fw)
 * @metadata_size:  size of @metadata in bytes
 * @fw:             mapped base of the loaded firmware carveout
 * @fw_size:        size of the carveout mapping in bytes
 * @fw_phys:        carveout physical base; used as relocation base for
 *                  non-relocatable images (not present in carveout)
 */
struct pas_auth_core_ctx {
	uint32_t hash_algo;
	uint32_t hash_size;
	const uint8_t *hash_table;
	uint32_t num_entries;
	const uint8_t *metadata;
	size_t metadata_size;
	const uint8_t *fw;
	size_t fw_size;
	paddr_t fw_phys;
};

/*
 * pas_auth_core_verify_segments() - verify loaded image against hash table
 * @ctx: integrity-check context
 *
 * Verifies entry 0 (ELF header + phdr table from @ctx->metadata) and each
 * loadable hashed segment at its loaded carveout offset (p_paddr - reloc_base).
 * Fails closed on first mismatch.
 *
 * Return TEE_SUCCESS, TEE_ERROR_SECURITY on mismatch, or an error on bad input.
 */
TEE_Result pas_auth_core_verify_segments(const struct pas_auth_core_ctx *ctx);

#endif /* __PAS_AUTH_CORE_H */
