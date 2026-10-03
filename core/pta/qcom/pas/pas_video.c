// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <elf32.h>
#include <elf64.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "pas_elf.h"
#include "pas_video.h"

/* Largest seed accepted */
#define SEED_MAX_SIZE	SMALL_PAGE_SIZE

struct seg_info {
	uint64_t paddr;
	uint64_t mem_len;
	uint32_t type;
	uint32_t flags;
};

static void get_seg(const uint8_t *phdr, bool is_64, struct seg_info *seg)
{
	if (is_64) {
		Elf64_Phdr p = { };

		memcpy(&p, phdr, sizeof(p));
		seg->paddr = p.p_paddr;
		seg->mem_len = p.p_memsz;
		seg->type = p.p_type;
		seg->flags = p.p_flags;
	} else {
		Elf32_Phdr p = { };

		memcpy(&p, phdr, sizeof(p));
		seg->paddr = p.p_paddr;
		seg->mem_len = p.p_memsz;
		seg->type = p.p_type;
		seg->flags = p.p_flags;
	}
}

static bool seg_is_loaded(const struct seg_info *seg)
{
	return pas_elf_is_image_seg(seg->type, seg->flags) && seg->mem_len;
}

TEE_Result pas_video_find_seed(const void *metadata, size_t size,
			       struct pas_video_seed *seed)
{
	const uint8_t *md = metadata;
	uint8_t ident[EI_NIDENT] = { };
	struct seg_info last = { };
	struct seg_info seg = { };
	uint64_t base = UINT64_MAX;
	uint64_t phoff = 0;
	uint64_t len = 0;
	size_t phentsize = 0;
	size_t phnum = 0;
	size_t n = 0;
	bool is_64 = false;

	pas_video_clear_seed(seed);

	if (!md || size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	/* The metadata may change under us: decide on a copy */
	memcpy(ident, md, sizeof(ident));
	if (memcmp(ident, ELFMAG, SELFMAG))
		return TEE_ERROR_BAD_FORMAT;

	if (ident[EI_CLASS] == ELFCLASS64) {
		Elf64_Ehdr ehdr = { };

		if (size < sizeof(ehdr))
			return TEE_ERROR_BAD_FORMAT;
		memcpy(&ehdr, md, sizeof(ehdr));
		phoff = ehdr.e_phoff;
		phnum = ehdr.e_phnum;
		phentsize = ehdr.e_phentsize;
		is_64 = true;
		if (phentsize != sizeof(Elf64_Phdr))
			return TEE_ERROR_BAD_FORMAT;
	} else if (ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr ehdr = { };

		if (size < sizeof(ehdr))
			return TEE_ERROR_BAD_FORMAT;
		memcpy(&ehdr, md, sizeof(ehdr));
		phoff = ehdr.e_phoff;
		phnum = ehdr.e_phnum;
		phentsize = ehdr.e_phentsize;
		if (phentsize != sizeof(Elf32_Phdr))
			return TEE_ERROR_BAD_FORMAT;
	} else {
		return TEE_ERROR_BAD_FORMAT;
	}

	if (!phnum || MUL_OVERFLOW(phnum, phentsize, &len) ||
	    ADD_OVERFLOW(len, phoff, &len) || len > size)
		return TEE_ERROR_BAD_FORMAT;

	/* Segments are placed relative to the lowest one */
	for (n = 0; n < phnum; n++) {
		get_seg(md + phoff + n * phentsize, is_64, &seg);
		if (seg_is_loaded(&seg))
			base = MIN(base, seg.paddr);
		if (n == phnum - 1)
			last = seg;
	}

	if (seg_is_loaded(&last)) {
		if (last.mem_len > SEED_MAX_SIZE ||
		    SUB_OVERFLOW(last.paddr, base, &seed->offset)) {
			seed->offset = 0;
			return TEE_ERROR_BAD_FORMAT;
		}
		seed->size = last.mem_len;
	}
	seed->valid = true;

	return TEE_SUCCESS;
}

TEE_Result pas_video_fill_seed(const struct qcom_pas_data *data,
			       struct pas_video_seed *seed)
{
	struct pas_video_seed s = *seed;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool mapped = false;
	paddr_t pa = 0;
	size_t end = 0;
	void *va = NULL;

	pas_video_clear_seed(seed);

	if (!s.valid)
		return TEE_ERROR_BAD_STATE;

	if (!s.size)
		return TEE_SUCCESS;

	if (ADD_OVERFLOW(s.offset, s.size, &end) || end > data->fw_size ||
	    ADD_OVERFLOW(data->fw_base, s.offset, &pa) ||
	    !core_pbuf_is(CORE_MEM_NON_SEC, pa, s.size))
		return TEE_ERROR_SECURITY;

	/* Only a mapping added here is removed here */
	va = phys_to_virt(pa, MEM_AREA_RAM_NSEC, s.size);
	if (!va) {
		va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, s.size);
		if (!va)
			return TEE_ERROR_GENERIC;
		mapped = true;
	}

	res = crypto_rng_read(va, s.size);
	if (!res)
		res = cache_op_inner(DCACHE_AREA_CLEAN, va, s.size);

	if (mapped && core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, va, s.size)) {
		EMSG("Failed to unmap the video firmware seed");
		if (!res)
			res = TEE_ERROR_GENERIC;
	}

	return res;
}
