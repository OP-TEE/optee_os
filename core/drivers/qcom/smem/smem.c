// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <inttypes.h>
#include <io.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "smem_internal.h"
#include "smem_plat.h"

static struct qcom_smem_info qcom_smem_info;

static TEE_Result smem_validate_toc_entry(const struct qcom_smem_toc_entry *e)
{
	uint32_t off = get_unaligned_le32(&e->offset);
	uint32_t sz = get_unaligned_le32(&e->size);
	uint64_t end = 0;

	/* Partition must be large enough to hold the partition header. */
	if (sz < sizeof(struct qcom_smem_partition_header))
		return TEE_ERROR_BAD_FORMAT;
	/* offset + size must not overflow and must lie within SMEM. */
	end = (uint64_t)off + sz;
	if (off < QCOM_SMEM_BOOT_INFO_SIZE ||
	    end > qcom_smem_info.toc_offset)
		return TEE_ERROR_BAD_FORMAT;
	return TEE_SUCCESS;
}

static bool smem_part_involves_local(const struct qcom_smem_toc_entry *e)
{
	uint16_t lh = qcom_smem_info.local_host;
	uint16_t h0 = get_unaligned_le16(&e->host0);
	uint16_t h1 = get_unaligned_le16(&e->host1);

	/* Common partition - accessible to all hosts. */
	if (h0 == QCOM_SMEM_HOST_COMMON && h1 == QCOM_SMEM_HOST_COMMON)
		return true;

	/* Edge-pair partition: local host is one endpoint. */
	return h0 == lh || h1 == lh;
}

static bool smem_part_matches(const struct qcom_smem_toc_entry *e,
			      uint16_t host)
{
	uint16_t lh = qcom_smem_info.local_host;
	uint16_t rh = host;
	uint16_t h0 = get_unaligned_le16(&e->host0);
	uint16_t h1 = get_unaligned_le16(&e->host1);

	/* Common partition lookup. */
	if (host == QCOM_SMEM_HOST_COMMON)
		return h0 == QCOM_SMEM_HOST_COMMON &&
		       h1 == QCOM_SMEM_HOST_COMMON;

	/* Edge-pair: one endpoint must be local, the other must be remote. */
	return (h0 == lh && h1 == rh) || (h0 == rh && h1 == lh);
}

static TEE_Result smem_scan_uncached(const uint8_t *base, uint32_t scan_limit,
				     uint16_t item_id, void **addr,
				     size_t *size)
{
	vaddr_t limit = 0;
	vaddr_t ptr = 0;
	const struct qcom_smem_item_header *ihdr = NULL;
	uint32_t item_size = 0;
	uint32_t step = 0;

	if (scan_limit < sizeof(struct qcom_smem_partition_header))
		return TEE_ERROR_BAD_FORMAT;

	limit = (vaddr_t)base + scan_limit;

	for (ptr = (vaddr_t)base + sizeof(struct qcom_smem_partition_header);
	     ptr < limit; ptr += step) {
		if (limit - ptr < sizeof(struct qcom_smem_item_header))
			return TEE_ERROR_BAD_FORMAT;

		ihdr = (const void *)ptr;

		if (get_unaligned_le16(&ihdr->canary) != QCOM_SMEM_ITEM_CANARY)
			return TEE_ERROR_BAD_FORMAT;

		item_size = get_unaligned_le32(&ihdr->size);

		if (item_size == 0)
			return TEE_ERROR_BAD_FORMAT;
		if (get_unaligned_le16(&ihdr->padding_data) > item_size)
			return TEE_ERROR_BAD_FORMAT;

		if (ADD_OVERFLOW(
			    sizeof(struct qcom_smem_item_header) +
				    get_unaligned_le16(&ihdr->padding_header),
			    item_size, &step))
			return TEE_ERROR_BAD_FORMAT;
		if (limit - ptr < step)
			return TEE_ERROR_BAD_FORMAT;

		if (get_unaligned_le16(&ihdr->item) != item_id)
			continue;

		*addr = (void *)(ptr + sizeof(struct qcom_smem_item_header) +
				 get_unaligned_le16(&ihdr->padding_header));
		if (size) {
			size_t pad = get_unaligned_le16(&ihdr->padding_data);

			*size = item_size - pad;
		}
		goto out;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
out:
	return TEE_SUCCESS;
}

static TEE_Result smem_search_partition(uint32_t part_offset,
					uint32_t part_size, uint16_t item_id,
					void **addr, size_t *size)
{
	const struct qcom_smem_partition_header *phdr = NULL;
	void *va = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t offset_free_uncached = 0;
	uint32_t offset_free_cached = 0;
	uint32_t min_uncached = 0;

	/* Validate partition range before any memory access. */
	if (part_size < sizeof(struct qcom_smem_partition_header))
		return TEE_ERROR_BAD_FORMAT;
	if ((uint64_t)part_offset + part_size > qcom_smem_info.smem_size)
		return TEE_ERROR_BAD_FORMAT;

	va = qcom_smem_plat_get_addr(part_offset);
	if (!va)
		return TEE_ERROR_ACCESS_DENIED;

	phdr = va;

	/*
	 * Validate static partition fields.
	 * magic and size are written once at partition creation time and
	 * never change, so they can be read without the HW lock.
	 */
	if (get_unaligned_le32(&phdr->magic) != QCOM_SMEM_PART_MAGIC) {
		EMSG("smem: bad partition magic 0x%08" PRIx32,
		     get_unaligned_le32(&phdr->magic));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (get_unaligned_le32(&phdr->size) != part_size) {
		EMSG("smem: partition size mismatch (header=%" PRIu32
		     " toc=%" PRIu32 ")",
		     get_unaligned_le32(&phdr->size),
		     part_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Read mutable heap pointers. */
	offset_free_uncached = get_unaligned_le32(&phdr->offset_free_uncached);
	offset_free_cached = get_unaligned_le32(&phdr->offset_free_cached);

	/*
	 * Validate heap pointers:
	 *   offset_free_uncached >= sizeof(partition_header)
	 *   offset_free_uncached <= offset_free_cached
	 *   offset_free_cached   <= part_size
	 */
	min_uncached = sizeof(struct qcom_smem_partition_header);
	if (offset_free_uncached < min_uncached ||
	    offset_free_uncached > offset_free_cached ||
	    offset_free_cached > part_size) {
		EMSG("smem: bad heap pointers uncached=%" PRIu32
		     " cached=%" PRIu32 " size=%" PRIu32,
		     offset_free_uncached,
		     offset_free_cached, part_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	res = smem_scan_uncached(va, offset_free_uncached,
				 item_id, addr, size);

	return res;
}

static TEE_Result
smem_validate_boot_version(const struct qcom_smem_static_header *static_hdr)
{
	uint32_t boot_version = 0;
	uint32_t boot_major = 0;
	uint32_t local_major = 0;

	boot_version = get_unaligned_le32(
		&static_hdr->ver[QCOM_SMEM_VERSION_BOOT_OFFSET]);
	boot_major = boot_version & QCOM_SMEM_MAJOR_VERSION_MASK;
	local_major = QCOM_SMEM_VERSION_ID & QCOM_SMEM_MAJOR_VERSION_MASK;

	if (boot_major != local_major) {
		EMSG("smem: BOOT version mismatch: 0x%08" PRIx32
		     " vs 0x%08" PRIx32,
		     boot_version, local_major);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result
smem_validate_toc_header(const struct qcom_smem_toc_header *toc,
			 uint32_t *num_entries_out)
{
	uint32_t num_entries = 0;

	if (get_unaligned_le32(&toc->magic) != QCOM_SMEM_TOC_MAGIC) {
		EMSG("smem: bad TOC magic 0x%08" PRIx32,
		     get_unaligned_le32(&toc->magic));
		return TEE_ERROR_BAD_FORMAT;
	}

	if (get_unaligned_le32(&toc->version) != QCOM_SMEM_TOC_VERSION) {
		EMSG("smem: unsupported TOC version %" PRIu32,
		     get_unaligned_le32(&toc->version));
		return TEE_ERROR_NOT_SUPPORTED;
	}

	num_entries = get_unaligned_le32(&toc->num_entries);
	if (num_entries == 0 || num_entries > QCOM_SMEM_TOC_MAX_ENTRIES) {
		EMSG("smem: invalid TOC num_entries %" PRIu32,
		     num_entries);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Entries array must fit within the TOC page. */
	if (sizeof(struct qcom_smem_toc_header) +
		    num_entries * sizeof(struct qcom_smem_toc_entry) >
	    QCOM_SMEM_TOC_SIZE) {
		EMSG("smem: TOC entries overflow TOC page");
		return TEE_ERROR_BAD_FORMAT;
	}

	*num_entries_out = num_entries;
	return TEE_SUCCESS;
}

static TEE_Result smem_map_partitions(const struct qcom_smem_toc_entry *entries,
				      uint32_t num_entries)
{
	uint32_t i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (i = 0; i < num_entries; i++) {
		const struct qcom_smem_toc_entry *e = &entries[i];

		if (smem_validate_toc_entry(e))
			continue; /* skip malformed entries silently */

		if (!smem_part_involves_local(e))
			continue; /* not relevant partition - do not map */

		res = qcom_smem_plat_map(get_unaligned_le32(&e->offset),
					 get_unaligned_le32(&e->size),
					 QCOM_SMEM_PLAT_MAP_RW);
		if (res) {
			EMSG("smem: failed to map partition %" PRIu16
			     "/%" PRIu16 ": %#" PRIx32,
			     get_unaligned_le16(&e->host0),
			     get_unaligned_le16(&e->host1),
			     res);
			return res;
		}

		if (get_unaligned_le16(&e->host0) == QCOM_SMEM_HOST_COMMON &&
		    get_unaligned_le16(&e->host1) == QCOM_SMEM_HOST_COMMON &&
		    qcom_smem_info.common_part_offset == 0) {
			qcom_smem_info.common_part_offset =
				get_unaligned_le32(&e->offset);
			qcom_smem_info.common_part_size =
				get_unaligned_le32(&e->size);
		}
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_smem_host_id(uint16_t proc_id, uint16_t proc_num,
			     uint16_t pd_num, uint16_t chiplet, uint16_t *host)
{
	uint16_t encoded = 0;

	if (!host)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Range checks: each field must fit in its allocated bit-width. */
	if (proc_id > HOST_PROC_ID_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	if (proc_num > HOST_PROC_NUM_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	if (pd_num > HOST_PD_NUM_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	if (chiplet > HOST_CHIPLET_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	encoded = SHIFT_U32(proc_id, HOST_PROC_ID_SHIFT) |
		  SHIFT_U32(proc_num, HOST_PROC_NUM_SHIFT) |
		  SHIFT_U32(pd_num, HOST_PD_NUM_SHIFT) |
		  SHIFT_U32(chiplet, HOST_CHIPLET_SHIFT);

	/*
	 * Reject any encoding that collides with a reserved/special host.
	 * These checks protect against accidental construction of reserved
	 * values even when the individual field ranges permit it.
	 */
	if (encoded == QCOM_SMEM_HOST_COMMON)
		return TEE_ERROR_BAD_PARAMETERS;
	if (encoded == QCOM_SMEM_HOST_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;
	if (encoded == QCOM_SMEM_HOST_MULTIHOST)
		return TEE_ERROR_BAD_PARAMETERS;

	*host = encoded;
	return TEE_SUCCESS;
}

/*
 * qcom_smem_init() - Initialize the SMEM common core.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if already initialized,
 * or another TEE_ERROR_* value on failure.
 */
TEE_Result qcom_smem_init(void)
{
	struct qcom_smem_plat_info plat_info = { };
	const struct qcom_smem_static_header *static_hdr = NULL;
	const struct qcom_smem_toc_header *toc = NULL;
	const struct qcom_smem_toc_entry *entries = NULL;
	void *va = NULL;
	uint32_t smem_size = 0;
	uint32_t toc_offset = 0;
	uint32_t num_entries = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (qcom_smem_info.initialized)
		return TEE_ERROR_BAD_STATE;

	res = qcom_smem_plat_init(&plat_info);
	if (res)
		return res;

	if (plat_info.local_host == QCOM_SMEM_HOST_INVALID) {
		EMSG("smem: invalid local_host");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * smem_size must hold at least the BOOT info page and the TOC page
	 * without overlap.  The constant sum cannot overflow size_t.
	 */
	if (plat_info.smem_size < QCOM_SMEM_BOOT_INFO_SIZE + QCOM_SMEM_TOC_SIZE) {
		EMSG("smem: smem_size too small");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* smem_size must fit in uint32_t (offsets are uint32_t). */
	if (plat_info.smem_size > UINT32_MAX) {
		EMSG("smem: smem_size exceeds uint32_t");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (plat_info.max_items == 0) {
		EMSG("smem: max_items is zero");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	smem_size = plat_info.smem_size;
	toc_offset = smem_size - QCOM_SMEM_TOC_SIZE;

	res = qcom_smem_plat_map(0, QCOM_SMEM_BOOT_INFO_SIZE,
				 QCOM_SMEM_PLAT_MAP_RO);
	if (res) {
		EMSG("smem: failed to map BOOT info: %#" PRIx32, res);
		goto err;
	}

	va = qcom_smem_plat_get_addr(0);
	if (!va) {
		EMSG("smem: BOOT info not mapped");
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	static_hdr = va;

	res = smem_validate_boot_version(static_hdr);
	if (res)
		goto err;

	res = qcom_smem_plat_map(toc_offset, QCOM_SMEM_TOC_SIZE,
				 QCOM_SMEM_PLAT_MAP_RO);
	if (res) {
		EMSG("smem: failed to map TOC: %#" PRIx32, res);
		goto err;
	}

	va = qcom_smem_plat_get_addr(toc_offset);
	if (!va) {
		EMSG("smem: TOC not mapped");
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	toc = va;
	entries = (const void *)(toc + 1);

	res = smem_validate_toc_header(toc, &num_entries);
	if (res)
		goto err;

	/*
	 * Populate qcom_smem_info fields needed by smem_validate_toc_entry(),
	 * smem_part_involves_local(), and smem_map_partitions() before
	 * calling them.
	 */
	qcom_smem_info.local_host = plat_info.local_host;
	qcom_smem_info.max_items = plat_info.max_items;
	qcom_smem_info.smem_size = smem_size;
	qcom_smem_info.toc_offset = toc_offset;
	qcom_smem_info.num_toc_entries = num_entries;

	res = smem_map_partitions(entries, num_entries);
	if (res)
		goto err;

	qcom_smem_info.initialized = true;

	return TEE_SUCCESS;

err:
	/* Roll back mappings and partially populated state. */
	qcom_smem_plat_unmap_all();
	memset(&qcom_smem_info, 0, sizeof(qcom_smem_info));

	return res;
}

/*
 * qcom_smem_lookup() - Look up an existing SMEM item.
 *
 * Fast path (QCOM_SMEM_HOST_COMMON):
 *   Uses the cached common_part_offset / common_part_size from
 *   qcom_smem_info to call smem_search_partition() directly, bypassing
 *   the TOC walk entirely.
 *
 * Slow path (edge-pair host):
 *   Walks the TOC to find a partition matching the requested host pair,
 *   then calls smem_search_partition() for the first matching entry.
 */
TEE_Result qcom_smem_lookup(uint16_t remote_host, uint16_t item, uint32_t flags,
			    void **item_ptr, size_t *item_size)
{
	const struct qcom_smem_toc_header *toc = NULL;
	const struct qcom_smem_toc_entry *entries = NULL;
	uint32_t i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Validate arguments. */
	if (!item_ptr)
		return TEE_ERROR_BAD_PARAMETERS;
	if (remote_host == QCOM_SMEM_HOST_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;
	if (flags)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!qcom_smem_info.initialized)
		return TEE_ERROR_BAD_STATE;

	if (item >= qcom_smem_info.max_items)
		return TEE_ERROR_BAD_PARAMETERS;

	if (remote_host == QCOM_SMEM_HOST_COMMON) {
		uint32_t offs = qcom_smem_info.common_part_offset;
		uint32_t sz = qcom_smem_info.common_part_size;

		if (offs || sz)
			return smem_search_partition(offs, sz, item, item_ptr,
						     item_size);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/*
	 * Slow path: edge-pair partition lookup.
	 *
	 * Walk the TOC looking for a partition matching {local_host, host}.
	 * First matching valid partition wins.
	 */
	toc = qcom_smem_plat_get_addr(qcom_smem_info.toc_offset);
	if (!toc)
		return TEE_ERROR_BAD_FORMAT;

	entries = (const void *)(toc + 1);

	for (i = 0; i < qcom_smem_info.num_toc_entries; i++) {
		const struct qcom_smem_toc_entry *e = &entries[i];

		if (smem_validate_toc_entry(e))
			continue;

		if (!smem_part_matches(e, remote_host))
			continue;

		res = smem_search_partition(get_unaligned_le32(&e->offset),
					    get_unaligned_le32(&e->size), item,
					    item_ptr, item_size);
		if (res != TEE_ERROR_ITEM_NOT_FOUND)
			return res;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

early_init(qcom_smem_init);
