// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <inttypes.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#include "sec_elf_v2.h"

TEE_Result sec_elf_parse(const uint8_t *data, size_t size,
			 const struct secdat_hdr **hdr,
			 const struct segment_hdr **segments)
{
	const struct secdat_hdr *header = NULL;

	if (!data || !hdr || !segments)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size < sizeof(struct secdat_hdr)) {
		EMSG("sec.elf too small: %zu bytes", size);
		return TEE_ERROR_BAD_FORMAT;
	}

	header = (const struct secdat_hdr *)data;

	if (header->magic1 != SECDAT_MAGIC1) {
		EMSG("Invalid magic1: 0x%08"PRIx32, header->magic1);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->magic2 != SECDAT_MAGIC2) {
		EMSG("Invalid magic2: 0x%08"PRIx32, header->magic2);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->revision != SECDAT_VERSION_2) {
		EMSG("Unsupported version: 0x%08"PRIx32, header->revision);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->size + sizeof(*header) + sizeof(struct secdat_footer) !=
	    size) {
		EMSG("Size mismatch: header=%"PRIu32 ", file=%zu",
		     header->size, size);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->seg_num > SECDAT_MAX_SUPPORTED_SEGMENT) {
		EMSG("Too many segments: %"PRIu32, header->seg_num);
		return TEE_ERROR_BAD_FORMAT;
	}

	*hdr = header;
	*segments = (const struct segment_hdr *)(data + sizeof(*header));

	return TEE_SUCCESS;
}

static TEE_Result sec_elf_validate_header(const uint8_t *data, size_t size,
					  const struct secdat_hdr **hdr)
{
	const struct secdat_hdr *header = NULL;

	if (!data || !hdr)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size < sizeof(struct secdat_hdr)) {
		EMSG("sec.elf too small: %zu bytes", size);
		return TEE_ERROR_BAD_FORMAT;
	}

	header = (const struct secdat_hdr *)data;

	if (header->magic1 != SECDAT_MAGIC1 ||
	    header->magic2 != SECDAT_MAGIC2) {
		EMSG("Invalid magic numbers");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->revision != SECDAT_VERSION_2) {
		EMSG("Unsupported version: 0x%08"PRIx32, header->revision);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->size + sizeof(*header) + sizeof(struct secdat_footer) !=
	    size) {
		EMSG("Size mismatch: header=%"PRIu32 ", file=%zu",
		     header->size, size);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (header->seg_num > SECDAT_MAX_SUPPORTED_SEGMENT) {
		EMSG("Too many segments: %"PRIu32, header->seg_num);
		return TEE_ERROR_BAD_FORMAT;
	}

	*hdr = header;
	return TEE_SUCCESS;
}

TEE_Result sec_elf_validate_hash(const uint8_t *data, size_t size,
				 const struct secdat_hdr *hdr)
{
	uint8_t calc_hash[TEE_SHA256_HASH_SIZE] = {0};
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *stored_hash = NULL;
	size_t hash_bytes = 0;
	void *ctx = NULL;

	if (!data || !hdr)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Calculate hash over header, segments, and data payload.
	 * The footer contains the stored hash for verification.
	 */
	hash_bytes = sizeof(struct secdat_hdr) +
		     (hdr->seg_num * sizeof(struct segment_hdr)) +
		     (hdr->size - sizeof(struct secdat_footer));

	if (hash_bytes >= size) {
		EMSG("Invalid hash size calculation: %zu >= %zu",
		     hash_bytes, size);
		return TEE_ERROR_BAD_FORMAT;
	}

	stored_hash = data + hash_bytes;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate hash context: 0x%"PRIx32, res);
		goto out;
	}

	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to initialize hash: 0x%"PRIx32, res);
		goto out;
	}

	res = crypto_hash_update(ctx, data, hash_bytes);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to update hash: 0x%"PRIx32, res);
		goto out;
	}

	res = crypto_hash_final(ctx, calc_hash, TEE_SHA256_HASH_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to finalize hash: 0x%"PRIx32, res);
		goto out;
	}

	if (consttime_memcmp(calc_hash, stored_hash,
			     TEE_SHA256_HASH_SIZE) != 0) {
		EMSG("Hash verification failed");
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	DMSG("Hash validation successful");
	res = TEE_SUCCESS;

out:
	crypto_hash_free_ctx(ctx);
	return res;
}

TEE_Result sec_elf_find_segment(const uint8_t *data, size_t size,
				uint32_t seg_type,
				const uint8_t **seg_data,
				uint32_t *seg_size)
{
	const struct segment_hdr *segments = NULL;
	const struct secdat_hdr *hdr = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t i = 0;

	if (!data || !seg_data || !seg_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = sec_elf_validate_header(data, size, &hdr);
	if (res != TEE_SUCCESS)
		return res;

	segments = (const struct segment_hdr *)(data + sizeof(*hdr));

	for (i = 0; i < hdr->seg_num; i++) {
		if (segments[i].type == seg_type) {
			if (segments[i].offset >= size) {
				EMSG("Invalid segment offset: %"PRIu32,
				     segments[i].offset);
				return TEE_ERROR_BAD_FORMAT;
			}

			*seg_data = data + segments[i].offset;

			/*
			 * Calculate segment size:
			 * - If not the last segment, size is the difference
			 *   between this segment's offset and the next
			 * - If last segment, size extends to the footer
			 */
			if ((i + 1) < hdr->seg_num) {
				/* Not the last segment */
				*seg_size = segments[i + 1].offset -
					    segments[i].offset;
			} else {
				/* Last segment */
				*seg_size = size -
					    sizeof(struct secdat_footer) -
					    segments[i].offset;
			}

			return TEE_SUCCESS;
		}
	}

	*seg_data = NULL;
	*seg_size = 0;
	return TEE_ERROR_ITEM_NOT_FOUND;
}
