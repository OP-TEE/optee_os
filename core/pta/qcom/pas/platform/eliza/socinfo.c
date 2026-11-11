// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Minimal reader of the SMEM socinfo item: the global partition named in
 * the SMEM partition table, walked for the item's uncached entry.
 */

#include <compiler.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>

#include "socinfo.h"

#define SMEM_PTABLE_OFFSET	(SMEM_SIZE - 0x1000)
#define SMEM_GLOBAL_HOST	0xfffe
#define SMEM_PRIVATE_CANARY	0xa5a5
#define SMEM_ITEM_SOCINFO	137

struct smem_ptable_entry {
	uint32_t offset;
	uint32_t size;
	uint32_t flags;
	uint16_t host0;
	uint16_t host1;
	uint32_t cacheline;
	uint32_t reserved[7];
} __packed;

struct smem_ptable {
	uint8_t magic[4];
	uint32_t version;
	uint32_t num_entries;
	uint32_t reserved[5];
	struct smem_ptable_entry entry[];
} __packed;

struct smem_partition_header {
	uint8_t magic[4];
	uint16_t host0;
	uint16_t host1;
	uint32_t size;
	uint32_t offset_free_uncached;
	uint32_t offset_free_cached;
	uint32_t reserved[3];
} __packed;

struct smem_private_entry {
	uint16_t canary;
	uint16_t item;
	uint32_t size;
	uint16_t padding_data;
	uint16_t padding_hdr;
	uint32_t reserved;
} __packed;

/* The fields of the socinfo item this reader needs (format 0.1 to 0.6) */
struct socinfo {
	uint32_t fmt;
	uint32_t id;
	uint32_t ver;
	char build_id[32];
	uint32_t raw_id;
	uint32_t raw_ver;
	uint32_t hw_plat;
	uint32_t plat_ver;
	uint32_t accessory_chip;
	uint32_t hw_plat_subtype;
} __packed;

static const uint8_t ptable_magic[] = { '$', 'T', 'O', 'C' };
static const uint8_t part_magic[] = { '$', 'P', 'R', 'T' };

/*
 * The normal world can rewrite SMEM at any time: read the entry count once
 * and use only checked copies of the entries and headers
 */
static const void *smem_find(vaddr_t smem, uint16_t item, size_t *size)
{
	const struct smem_ptable *pt = (void *)(smem + SMEM_PTABLE_OFFSET);
	struct smem_partition_header ph = { };
	struct smem_ptable_entry pe = { };
	struct smem_private_entry e = { };
	vaddr_t part = 0;
	vaddr_t end = 0;
	vaddr_t p = 0;
	uint32_t n = 0;

	if (memcmp(pt->magic, ptable_magic, sizeof(ptable_magic)))
		return NULL;

	n = MIN(pt->num_entries,
		(uint32_t)((0x1000 - sizeof(*pt)) / sizeof(pt->entry[0])));
	for (uint32_t i = 0; i < n; i++) {
		memcpy(&pe, &pt->entry[i], sizeof(pe));
		if (pe.host0 != SMEM_GLOBAL_HOST ||
		    pe.host1 != SMEM_GLOBAL_HOST)
			continue;
		if (!pe.offset || pe.offset >= SMEM_SIZE ||
		    pe.size > SMEM_SIZE - pe.offset || pe.size < sizeof(ph))
			return NULL;
		part = smem + pe.offset;
		memcpy(&ph, (void *)part, sizeof(ph));
		if (memcmp(ph.magic, part_magic, sizeof(part_magic)) ||
		    ph.offset_free_uncached > pe.size)
			return NULL;
		end = part + ph.offset_free_uncached;
		break;
	}
	if (!part)
		return NULL;

	for (p = part + sizeof(ph); p + sizeof(e) <= end;
	     p += sizeof(e) + e.padding_hdr + e.size) {
		memcpy(&e, (void *)p, sizeof(e));
		if (e.canary != SMEM_PRIVATE_CANARY)
			return NULL;
		if (e.item != item)
			continue;
		if (p + sizeof(e) + e.padding_hdr + e.size > end ||
		    e.padding_data > e.size)
			return NULL;
		*size = e.size - e.padding_data;
		return (void *)(p + sizeof(e) + e.padding_hdr);
	}

	return NULL;
}

TEE_Result qcom_socinfo_read(struct qcom_socinfo *info)
{
	static struct qcom_socinfo cache;
	static bool cached;
	const struct socinfo *si = NULL;
	vaddr_t smem = 0;
	size_t size = 0;

	if (cached) {
		*info = cache;
		return TEE_SUCCESS;
	}

	/* SMEM is in the non-secure DDR: map it only to read the item */
	smem = (vaddr_t)core_mmu_add_mapping(MEM_AREA_RAM_NSEC, SMEM_BASE,
					     SMEM_SIZE);
	if (!smem)
		return TEE_ERROR_GENERIC;

	si = smem_find(smem, SMEM_ITEM_SOCINFO, &size);
	if (si && size >= sizeof(*si)) {
		cache.id = si->id;
		cache.version = si->ver;
		cache.platform = si->hw_plat;
		cache.platform_version = si->plat_ver;
		cache.platform_subtype = si->hw_plat_subtype;
		cached = true;
	}

	if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, (void *)smem,
				    SMEM_SIZE))
		EMSG("SMEM stays mapped");

	if (!cached) {
		EMSG("No socinfo in SMEM");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	*info = cache;
	return TEE_SUCCESS;
}
