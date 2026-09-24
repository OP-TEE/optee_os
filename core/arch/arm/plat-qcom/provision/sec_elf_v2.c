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

TEE_Result sec_elf_get_size(const uint8_t *data, size_t capacity, size_t *size)
{
	const struct secdat_hdr *hdr = NULL;
	size_t table_size = 0;
	size_t total = 0;

	if (!data || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	*size = 0;
	if (capacity < sizeof(*hdr))
		return TEE_ERROR_BAD_FORMAT;

	hdr = (const struct secdat_hdr *)data;
	if (hdr->magic1 != SECDAT_MAGIC1 || hdr->magic2 != SECDAT_MAGIC2 ||
	    hdr->revision != SECDAT_VERSION_2 ||
	    hdr->seg_num > SECDAT_MAX_SUPPORTED_SEGMENT ||
	    hdr->size < sizeof(struct secdat_footer))
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW((size_t)hdr->seg_num, sizeof(struct segment_hdr),
			 &table_size) ||
	    ADD_OVERFLOW(sizeof(*hdr), table_size, &total) ||
	    ADD_OVERFLOW(total, (size_t)hdr->size, &total) || total > capacity)
		return TEE_ERROR_BAD_FORMAT;

	*size = total;
	return TEE_SUCCESS;
}

static TEE_Result validate_fuse_list(const uint8_t *data, size_t size,
				     bool check_shk_count)
{
	const struct qfuse_list_hdr *hdr = NULL;
	const struct fuse_entry *entries = NULL;
	size_t entry_size = 0;
	uint32_t shk_count = 0;
	uint32_t n = 0;

	if (size < sizeof(*hdr))
		return TEE_ERROR_BAD_FORMAT;

	hdr = (const struct qfuse_list_hdr *)data;
	if (hdr->revision != SECDAT_FUSE_LIST_REVISION || !hdr->fuse_count ||
	    hdr->fuse_count > SECDAT_MAX_FUSES ||
	    MUL_OVERFLOW((size_t)hdr->fuse_count, sizeof(*entries),
			 &entry_size) ||
	    hdr->size != entry_size || entry_size > size - sizeof(*hdr))
		return TEE_ERROR_BAD_FORMAT;

	entries = (const struct fuse_entry *)(data + sizeof(*hdr));
	for (n = 0; n < hdr->fuse_count; n++) {
		if (entries[n].region >= FUSEPROV_REGION_MAX ||
		    (entries[n].operation != FUSEPROV_OP_BLOW &&
		     entries[n].operation != FUSEPROV_OP_BLOW_RANDOM))
			return TEE_ERROR_BAD_FORMAT;

		if (check_shk_count &&
		    entries[n].region == FUSEPROV_REGION_SHK &&
		    entries[n].operation == FUSEPROV_OP_BLOW &&
		    ++shk_count > SECDAT_MAX_SHK_ROWS)
			return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

TEE_Result sec_elf_parse(const uint8_t *data, size_t size,
			 const struct secdat_hdr **hdr,
			 const struct segment_hdr **segments)
{
	const struct segment_hdr *table = NULL;
	const struct secdat_hdr *header = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t payload_start = 0;
	size_t payload_end = 0;
	size_t image_size = 0;
	uint32_t n = 0;

	if (!hdr || !segments)
		return TEE_ERROR_BAD_PARAMETERS;

	*hdr = NULL;
	*segments = NULL;
	res = sec_elf_get_size(data, size, &image_size);
	if (res)
		return res;

	header = (const struct secdat_hdr *)data;
	table = (const struct segment_hdr *)(data + sizeof(*header));
	payload_start = sizeof(*header) + header->seg_num * sizeof(*table);
	payload_end = image_size - sizeof(struct secdat_footer);

	/* A footer-only payload is a valid no-fuse image. */
	if (header->size != sizeof(struct secdat_footer)) {
		for (n = 0; n < header->seg_num; n++) {
			bool efuse = table[n].type == SECDAT_SEGMENT_TYPE_EFUSE;
			size_t end = payload_end;

			if (n + 1 < header->seg_num)
				end = table[n + 1].offset;
			if (table[n].offset < payload_start ||
			    table[n].offset >= end || end > payload_end)
				return TEE_ERROR_BAD_FORMAT;

			if (efuse ||
			    table[n].type == SECDAT_SEGMENT_TYPE_ENCKEY) {
				res = validate_fuse_list(data + table[n].offset,
							 end - table[n].offset,
							 efuse);
				if (res)
					return res;
			}
		}
	}

	*hdr = header;
	*segments = table;
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

	res = sec_elf_get_size(data, size, &hash_bytes);
	if (res)
		return res;

	hash_bytes -= sizeof(struct secdat_footer);

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
	memzero_explicit(calc_hash, sizeof(calc_hash));
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
	size_t image_size = 0;
	uint32_t n = 0;

	if (!seg_data || !seg_size)
		return TEE_ERROR_BAD_PARAMETERS;

	*seg_data = NULL;
	*seg_size = 0;
	res = sec_elf_parse(data, size, &hdr, &segments);
	if (res)
		return res;

	res = sec_elf_get_size(data, size, &image_size);
	if (res)
		return res;

	if (hdr->size == sizeof(struct secdat_footer))
		return TEE_ERROR_ITEM_NOT_FOUND;

	for (n = 0; n < hdr->seg_num; n++) {
		if (segments[n].type == seg_type) {
			size_t end = image_size - sizeof(struct secdat_footer);

			if (n + 1 < hdr->seg_num)
				end = segments[n + 1].offset;
			*seg_data = data + segments[n].offset;
			*seg_size = end - segments[n].offset;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}
