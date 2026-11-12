// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Qualcomm Shared Memory (SMEM) - Common Core
 *
 */

#include <initcall.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "smem_internal.h"
#include "smem_plat.h"

/* -----------------------------------------------------------------------
 * Driver state instance
 * -----------------------------------------------------------------------
 */

/* Single static instance */
static struct qti_smem_info qti_smem_info;

/* -----------------------------------------------------------------------
 * Internal helpers
 * -----------------------------------------------------------------------
 */

static inline uint16_t smem_rd16(const void *ptr)
{
	uint16_t val;

	memcpy(&val, ptr, sizeof(val));
	return val;
}

static inline uint32_t smem_rd32(const void *ptr)
{
	uint32_t val;

	memcpy(&val, ptr, sizeof(val));
	return val;
}

static TEE_Result smem_validate_toc_entry(const struct qti_smem_toc_entry *e)
{
	uint32_t off = smem_rd32(&e->offset);
	uint32_t sz = smem_rd32(&e->size);
	uint64_t end;

	/* Partition must be large enough to hold the partition header. */
	if (sz < (uint32_t)sizeof(struct qti_smem_partition_header))
		return TEE_ERROR_BAD_FORMAT;
	/* offset + size must not overflow and must lie within SMEM. */
	end = (uint64_t)off + (uint64_t)sz;
	if (off < QTI_SMEM_BOOT_INFO_SIZE ||
	    end > (uint64_t)qti_smem_info.toc_offset)
		return TEE_ERROR_BAD_FORMAT;
	return TEE_SUCCESS;
}

static int smem_part_involves_local(const struct qti_smem_toc_entry *e)
{
	uint16_t lh = (uint16_t)qti_smem_info.local_host;
	uint16_t h0 = smem_rd16(&e->host0);
	uint16_t h1 = smem_rd16(&e->host1);

	/* Common partition - accessible to all hosts. */
	if (h0 == (uint16_t)QTI_SMEM_HOST_COMMON &&
	    h1 == (uint16_t)QTI_SMEM_HOST_COMMON) {
		return 1;
	}

	/* Edge-pair partition: local host is one endpoint. */
	return ((h0 == lh) || (h1 == lh)) ? 1 : 0;
}

static int smem_part_matches(const struct qti_smem_toc_entry *e, uint16_t host)
{
	uint16_t lh = (uint16_t)qti_smem_info.local_host;
	uint16_t rh = host;
	uint16_t h0 = smem_rd16(&e->host0);
	uint16_t h1 = smem_rd16(&e->host1);

	/* Common partition lookup. */
	if (host == QTI_SMEM_HOST_COMMON) {
		return ((h0 == (uint16_t)QTI_SMEM_HOST_COMMON) &&
			(h1 == (uint16_t)QTI_SMEM_HOST_COMMON)) ?
			       1 :
			       0;
	}

	/* Edge-pair: one endpoint must be local, the other must be remote. */
	return (((h0 == lh) && (h1 == rh)) || ((h0 == rh) && (h1 == lh))) ? 1 :
									    0;
}

static TEE_Result smem_scan_uncached(const uint8_t *base, uint32_t scan_limit,
				     uint16_t item_id, void **addr,
				     size_t *size)
{
	const uint8_t *limit;
	const uint8_t *ptr;
	const struct qti_smem_item_header *ihdr;
	uint32_t item_size;
	uint32_t step = 0U;

	if (scan_limit < (uint32_t)sizeof(struct qti_smem_partition_header))
		return TEE_ERROR_BAD_FORMAT;

	limit = base + scan_limit;

	for (ptr = base + sizeof(struct qti_smem_partition_header); ptr < limit;
	     ptr += (size_t)step) {
		if ((uintptr_t)limit - (uintptr_t)ptr <
		    sizeof(struct qti_smem_item_header))
			return TEE_ERROR_BAD_FORMAT;

		ihdr = (const struct qti_smem_item_header *)(const void *)ptr;

		if (smem_rd16(&ihdr->canary) != (uint16_t)QTI_SMEM_ITEM_CANARY)
			return TEE_ERROR_BAD_FORMAT;

		item_size = smem_rd32(&ihdr->size);

		if (item_size == 0U)
			return TEE_ERROR_BAD_FORMAT;
		if ((uint32_t)smem_rd16(&ihdr->padding_data) > item_size)
			return TEE_ERROR_BAD_FORMAT;

		step = (uint32_t)sizeof(struct qti_smem_item_header) +
		       (uint32_t)smem_rd16(&ihdr->padding_header) + item_size;
		if (step < item_size)
			return TEE_ERROR_BAD_FORMAT;
		if ((uintptr_t)limit - (uintptr_t)ptr < (uintptr_t)step)
			return TEE_ERROR_BAD_FORMAT;

		if (smem_rd16(&ihdr->item) != item_id)
			continue;

		*addr = (void *)(ptr + sizeof(struct qti_smem_item_header) +
				 (size_t)smem_rd16(&ihdr->padding_header));
		if (size) {
			size_t pad = (size_t)smem_rd16(&ihdr->padding_data);

			*size = (size_t)(item_size - pad);
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
	const struct qti_smem_partition_header *phdr;
	void *va;
	TEE_Result rc;
	uint32_t offset_free_uncached;
	uint32_t offset_free_cached;
	uint32_t min_uncached;

	/* Validate partition range before any memory access. */
	if (part_size < (uint32_t)sizeof(struct qti_smem_partition_header))
		return TEE_ERROR_BAD_FORMAT;
	if ((uint64_t)part_offset + (uint64_t)part_size >
	    (uint64_t)qti_smem_info.smem_size) {
		return TEE_ERROR_BAD_FORMAT;
	}

	va = qti_smem_plat_get_addr(part_offset);
	if (!va)
		return TEE_ERROR_ACCESS_DENIED;

	phdr = (const struct qti_smem_partition_header *)va;

	/*
	 * Validate static partition fields.
	 * magic and size are written once at partition creation time and
	 * never change, so they can be read without the HW lock.
	 */
	if (smem_rd32(&phdr->magic) != QTI_SMEM_PART_MAGIC) {
		EMSG("smem: bad partition magic 0x%08x\n",
		     (unsigned int)smem_rd32(&phdr->magic));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (smem_rd32(&phdr->size) != part_size) {
		EMSG("smem: partition size mismatch (header=%u toc=%u)\n",
		     (unsigned int)smem_rd32(&phdr->size),
		     (unsigned int)part_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Read mutable heap pointers. */
	offset_free_uncached = smem_rd32(&phdr->offset_free_uncached);
	offset_free_cached = smem_rd32(&phdr->offset_free_cached);

	/*
	 * Validate heap pointers:
	 *   offset_free_uncached >= sizeof(partition_header)
	 *   offset_free_uncached <= offset_free_cached
	 *   offset_free_cached   <= part_size
	 */
	min_uncached = (uint32_t)sizeof(struct qti_smem_partition_header);
	if (offset_free_uncached < min_uncached ||
	    offset_free_uncached > offset_free_cached ||
	    offset_free_cached > part_size) {
		EMSG("smem: bad heap pointers uncached=%u cached=%u size=%u\n",
		     (unsigned int)offset_free_uncached,
		     (unsigned int)offset_free_cached, (unsigned int)part_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	rc = smem_scan_uncached((const uint8_t *)va, offset_free_uncached,
				item_id, addr, size);

	return rc;
}

static TEE_Result
smem_validate_boot_version(const struct qti_smem_static_header *static_hdr)
{
	uint32_t boot_version;
	uint32_t boot_major;
	uint32_t local_major;

	boot_version =
		smem_rd32(&static_hdr->ver[QTI_SMEM_VERSION_BOOT_OFFSET]);
	boot_major = boot_version & QTI_SMEM_MAJOR_VERSION_MASK;
	local_major = QTI_SMEM_VERSION_ID & QTI_SMEM_MAJOR_VERSION_MASK;

	if (boot_major != local_major) {
		EMSG("smem: BOOT version mismatch: 0x%08x vs 0x%08x\n",
		     (unsigned int)boot_version, (unsigned int)local_major);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result
smem_validate_toc_header(const struct qti_smem_toc_header *toc,
			 uint32_t *num_entries_out)
{
	uint32_t num_entries;

	if (smem_rd32(&toc->magic) != QTI_SMEM_TOC_MAGIC) {
		EMSG("smem: bad TOC magic 0x%08x\n",
		     (unsigned int)smem_rd32(&toc->magic));
		return TEE_ERROR_BAD_FORMAT;
	}

	if (smem_rd32(&toc->version) != QTI_SMEM_TOC_VERSION) {
		EMSG("smem: unsupported TOC version %u\n",
		     (unsigned int)smem_rd32(&toc->version));
		return TEE_ERROR_NOT_SUPPORTED;
	}

	num_entries = smem_rd32(&toc->num_entries);
	if (num_entries == 0U || num_entries > QTI_SMEM_TOC_MAX_ENTRIES) {
		EMSG("smem: invalid TOC num_entries %u\n",
		     (unsigned int)num_entries);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Entries array must fit within the TOC page. */
	if ((uint32_t)sizeof(struct qti_smem_toc_header) +
		    num_entries * (uint32_t)sizeof(struct qti_smem_toc_entry) >
	    QTI_SMEM_TOC_SIZE) {
		EMSG("smem: TOC entries overflow TOC page\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	*num_entries_out = num_entries;
	return TEE_SUCCESS;
}

static TEE_Result smem_map_partitions(const struct qti_smem_toc_entry *entries,
				      uint32_t num_entries)
{
	uint32_t i;
	TEE_Result ret;

	for (i = 0U; i < num_entries; i++) {
		const struct qti_smem_toc_entry *e = &entries[i];

		if (smem_validate_toc_entry(e) != TEE_SUCCESS)
			continue; /* skip malformed entries silently */

		if (smem_part_involves_local(e) == 0)
			continue; /* not relevant partition - do not map */

		ret = qti_smem_plat_map(smem_rd32(&e->offset),
					(size_t)smem_rd32(&e->size),
					QTI_SMEM_PLAT_MAP_RW);
		if (ret != TEE_SUCCESS) {
			EMSG("smem: failed to map partition %u/%u: %#x\n",
			     (unsigned int)smem_rd16(&e->host0),
			     (unsigned int)smem_rd16(&e->host1),
			     (unsigned int)ret);
			return ret;
		}

		if (smem_rd16(&e->host0) == (uint16_t)QTI_SMEM_HOST_COMMON &&
		    smem_rd16(&e->host1) == (uint16_t)QTI_SMEM_HOST_COMMON &&
		    qti_smem_info.common_part_offset == 0U) {
			qti_smem_info.common_part_offset =
				smem_rd32(&e->offset);
			qti_smem_info.common_part_size = smem_rd32(&e->size);
		}
	}

	return TEE_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Public API
 * -----------------------------------------------------------------------
 */

TEE_Result qti_smem_host_id(uint16_t proc_id, uint16_t proc_num,
			    uint16_t pd_num, uint16_t chiplet, uint16_t *host)
{
	uint16_t encoded;

	if (!host)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Range checks: each field must fit in its allocated bit-width. */
	if ((uint32_t)proc_id > HOST_PROC_ID_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((uint32_t)proc_num > HOST_PROC_NUM_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((uint32_t)pd_num > HOST_PD_NUM_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((uint32_t)chiplet > HOST_CHIPLET_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	encoded = (uint16_t)(((uint16_t)proc_id << HOST_PROC_ID_SHIFT) |
			     ((uint16_t)proc_num << HOST_PROC_NUM_SHIFT) |
			     ((uint16_t)pd_num << HOST_PD_NUM_SHIFT) |
			     ((uint16_t)chiplet << HOST_CHIPLET_SHIFT));

	/*
	 * Reject any encoding that collides with a reserved/special host.
	 * These checks protect against accidental construction of reserved
	 * values even when the individual field ranges permit it.
	 */
	if (encoded == (uint16_t)QTI_SMEM_HOST_COMMON)
		return TEE_ERROR_BAD_PARAMETERS;
	if (encoded == (uint16_t)QTI_SMEM_HOST_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;
	if (encoded == (uint16_t)QTI_SMEM_HOST_MULTIHOST)
		return TEE_ERROR_BAD_PARAMETERS;

	*host = encoded;
	return TEE_SUCCESS;
}

/*
 * qti_smem_init() - Initialize the SMEM common core.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if already initialized,
 * or another TEE_ERROR_* value on failure.
 */
TEE_Result qti_smem_init(void)
{
	struct qti_smem_plat_info plat_info;
	const struct qti_smem_static_header *static_hdr;
	const struct qti_smem_toc_header *toc;
	const struct qti_smem_toc_entry *entries;
	void *va;
	uint32_t smem_size;
	uint32_t toc_offset;
	uint32_t num_entries;
	TEE_Result ret;

	if (qti_smem_info.initialized != 0)
		return TEE_ERROR_BAD_STATE;

	ret = qti_smem_plat_init(&plat_info);
	if (ret != TEE_SUCCESS)
		return ret;

	if (plat_info.local_host == (uint16_t)QTI_SMEM_HOST_INVALID) {
		EMSG("smem: invalid local_host\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * smem_size must hold at least the BOOT info page and the TOC page
	 * without overlap.  The constant sum cannot overflow size_t.
	 */
	if (plat_info.smem_size <
	    (size_t)(QTI_SMEM_BOOT_INFO_SIZE + QTI_SMEM_TOC_SIZE)) {
		EMSG("smem: smem_size too small\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* smem_size must fit in uint32_t (offsets are uint32_t). */
	if (plat_info.smem_size > (size_t)UINT32_MAX) {
		EMSG("smem: smem_size exceeds uint32_t\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (plat_info.max_items == 0U) {
		EMSG("smem: max_items is zero\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	smem_size = (uint32_t)plat_info.smem_size;
	toc_offset = smem_size - QTI_SMEM_TOC_SIZE;

	ret = qti_smem_plat_map(0U, QTI_SMEM_BOOT_INFO_SIZE,
				QTI_SMEM_PLAT_MAP_RO);
	if (ret != TEE_SUCCESS) {
		EMSG("smem: failed to map BOOT info: %#x\n", (unsigned int)ret);
		return ret;
	}

	va = qti_smem_plat_get_addr(0U);
	if (!va) {
		EMSG("smem: BOOT info not mapped\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	static_hdr = (const struct qti_smem_static_header *)va;

	ret = smem_validate_boot_version(static_hdr);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = qti_smem_plat_map(toc_offset, QTI_SMEM_TOC_SIZE,
				QTI_SMEM_PLAT_MAP_RO);
	if (ret != TEE_SUCCESS) {
		EMSG("smem: failed to map TOC: %#x\n", (unsigned int)ret);
		return ret;
	}

	va = qti_smem_plat_get_addr(toc_offset);
	if (!va) {
		EMSG("smem: TOC not mapped\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	toc = (const struct qti_smem_toc_header *)va;
	entries = (const struct qti_smem_toc_entry
			   *)((const uint8_t *)va +
			      sizeof(struct qti_smem_toc_header));

	ret = smem_validate_toc_header(toc, &num_entries);
	if (ret != TEE_SUCCESS)
		return ret;

	/*
	 * Populate qti_smem_info fields needed by smem_validate_toc_entry(),
	 * smem_part_involves_local(), and smem_map_partitions() before
	 * calling them.
	 */
	qti_smem_info.local_host = plat_info.local_host;
	qti_smem_info.max_items = plat_info.max_items;
	qti_smem_info.smem_size = smem_size;
	qti_smem_info.toc_offset = toc_offset;
	qti_smem_info.num_toc_entries = num_entries;

	ret = smem_map_partitions(entries, num_entries);
	if (ret != TEE_SUCCESS) {
		/* Roll back partially populated state. */
		memset(&qti_smem_info, 0, sizeof(qti_smem_info));
		return ret;
	}

	qti_smem_info.initialized = 1;

	return TEE_SUCCESS;
}

/*
 * qti_smem_lookup() - Look up an existing SMEM item.
 *
 * Fast path (QTI_SMEM_HOST_COMMON):
 *   Uses the cached common_part_offset / common_part_size from
 *   qti_smem_info to call smem_search_partition() directly, bypassing
 *   the TOC walk entirely.
 *
 * Slow path (edge-pair host):
 *   Walks the TOC to find a partition matching the requested host pair,
 *   then calls smem_search_partition() for the first matching entry.
 */
TEE_Result qti_smem_lookup(uint16_t remote_host, uint16_t item, uint32_t flags,
			   void **item_ptr, size_t *item_size)
{
	const struct qti_smem_toc_entry *entries;
	void *toc_va;
	uint32_t i;
	TEE_Result rc;

	/* Validate arguments. */
	if (!item_ptr)
		return TEE_ERROR_BAD_PARAMETERS;
	if (remote_host == QTI_SMEM_HOST_INVALID)
		return TEE_ERROR_BAD_PARAMETERS;
	if (flags != 0U)
		return TEE_ERROR_BAD_PARAMETERS;

	if (qti_smem_info.initialized == 0)
		return TEE_ERROR_BAD_STATE;

	if ((uint32_t)item >= (uint32_t)qti_smem_info.max_items)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Fast path: common partition lookup.
	 *
	 * The common partition offset and size were cached during
	 * qti_smem_init() by smem_map_partitions().  Use them directly
	 * to avoid walking the TOC on every common-partition lookup.
	 *
	 * If no common partition was found during init (common_part_offset
	 * == 0 and common_part_size == 0), continue below to the TOC walk
	 * which will also return TEE_ERROR_ITEM_NOT_FOUND.
	 */
	if (remote_host == QTI_SMEM_HOST_COMMON) {
		if (qti_smem_info.common_part_offset != 0U ||
		    qti_smem_info.common_part_size != 0U) {
			uint32_t common_offset =
				qti_smem_info.common_part_offset;
			uint32_t common_size =
				qti_smem_info.common_part_size;

			return smem_search_partition(common_offset,
						    common_size,
						    item, item_ptr,
						    item_size);
		}
		/* No common partition mapped - item cannot exist. */
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/*
	 * Slow path: edge-pair partition lookup.
	 *
	 * Walk the TOC looking for a partition matching {local_host, host}.
	 * First matching valid partition wins.
	 */
	toc_va = qti_smem_plat_get_addr(qti_smem_info.toc_offset);
	if (!toc_va)
		return TEE_ERROR_BAD_FORMAT;

	entries = (const struct qti_smem_toc_entry
			   *)((const uint8_t *)toc_va +
			      sizeof(struct qti_smem_toc_header));

	for (i = 0U; i < qti_smem_info.num_toc_entries; i++) {
		const struct qti_smem_toc_entry *e = &entries[i];

		if (smem_validate_toc_entry(e) != TEE_SUCCESS)
			continue;

		if (smem_part_matches(e, remote_host) == 0)
			continue;

		rc = smem_search_partition(smem_rd32(&e->offset),
					   smem_rd32(&e->size), item, item_ptr,
					   item_size);
		if (rc != TEE_ERROR_ITEM_NOT_FOUND)
			return rc; /* found, or hard error */
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

early_init(qti_smem_init);
