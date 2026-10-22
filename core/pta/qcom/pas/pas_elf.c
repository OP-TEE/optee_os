// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <elf32.h>
#include <elf64.h>
#include <mm/core_mmu.h>
#include <platform_pas.h>
#include <utee_defines.h>
#include <util.h>

#define MI_PBT_PAGE_MODE_MASK		0x00100000
#define MI_PBT_PAGE_MODE_SHIFT		20
#define MI_PBT_ACCESS_TYPE_MASK		0x00E00000
#define MI_PBT_ACCESS_TYPE_SHIFT	21
#define MI_PBT_SEGMENT_TYPE_MASK	0x07000000
#define MI_PBT_SEGMENT_TYPE_SHIFT	24

#define MI_PBT_NON_PAGED_SEGMENT	0x0
#define MI_PBT_HASH_SEGMENT		0x2
#define MI_PBT_NOTUSED_SEGMENT		0x3
#define MI_PBT_SHARED_SEGMENT		0x4

#define MI_PBT_PAGE_MODE(x) \
	(((x) & MI_PBT_PAGE_MODE_MASK) >> MI_PBT_PAGE_MODE_SHIFT)
#define MI_PBT_ACCESS_TYPE(x) \
	(((x) & MI_PBT_ACCESS_TYPE_MASK) >> MI_PBT_ACCESS_TYPE_SHIFT)
#define MI_PBT_SEGMENT_TYPE(x) \
	(((x) & MI_PBT_SEGMENT_TYPE_MASK) >> MI_PBT_SEGMENT_TYPE_SHIFT)

static inline void parse_ehdr(struct elf_info *e_info, const void *ehdr,
			      bool is_64)
{
	if (is_64) {
		const Elf64_Ehdr *e64 = ehdr;

		e_info->is_64 = true;
		e_info->elf_hdr_len = e64->e_ehsize;
		e_info->phdr_offset = e64->e_phoff;
		e_info->phdr_entry_len = e64->e_phentsize;
		e_info->phdr_count = e64->e_phnum;
		e_info->entry = e64->e_entry;
	} else {
		const Elf32_Ehdr *e32 = ehdr;

		e_info->is_64 = false;
		e_info->elf_hdr_len = e32->e_ehsize;
		e_info->phdr_offset = e32->e_phoff;
		e_info->phdr_entry_len = e32->e_phentsize;
		e_info->phdr_count = e32->e_phnum;
		e_info->entry = e32->e_entry;
	}
}

static inline void parse_phdr(struct phdr_info *p_info, const void *phdr,
			      bool is_64)
{
	if (is_64) {
		const Elf64_Phdr *p64 = phdr;

		p_info->paddr = p64->p_paddr;
		p_info->file_len = p64->p_filesz;
		p_info->mem_len = p64->p_memsz;
		p_info->type = p64->p_type;
		p_info->flags = p64->p_flags;
	} else {
		const Elf32_Phdr *p32 = phdr;

		p_info->paddr = p32->p_paddr;
		p_info->file_len = p32->p_filesz;
		p_info->mem_len = p32->p_memsz;
		p_info->type = p32->p_type;
		p_info->flags = p32->p_flags;
	}
}

bool pas_elf_is_hashed(uint32_t p_type, uint32_t p_flags)
{
	if (p_type != PT_LOAD)
		return false;

	return MI_PBT_PAGE_MODE(p_flags) == MI_PBT_NON_PAGED_SEGMENT &&
	       MI_PBT_SEGMENT_TYPE(p_flags) != MI_PBT_HASH_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_NOTUSED_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_SHARED_SEGMENT;
}

void pas_elf_get_phdr(const uint8_t *fw, const struct elf_info *e_info,
		      size_t idx, struct phdr_info *p_info)
{
	const uint8_t *p = fw + e_info->phdr_offset +
			   idx * e_info->phdr_entry_len;

	if (e_info->is_64) {
		const Elf64_Phdr *phdr = (const void *)p;

		parse_phdr(p_info, phdr, true);
	} else {
		const Elf32_Phdr *phdr = (const void *)p;

		parse_phdr(p_info, phdr, false);
	}
}

TEE_Result pas_elf_parse(const uint8_t *fw, size_t fw_size,
			 struct elf_info *e_info)
{
	const unsigned char *ident = fw;

	if (!fw || !e_info)
		return TEE_ERROR_BAD_PARAMETERS;

	if (fw_size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
		return TEE_ERROR_BAD_FORMAT;

	switch (ident[EI_CLASS]) {
	case ELFCLASS64: {
		const Elf64_Ehdr *ehdr = (const void *)fw;

		if (fw_size < sizeof(*ehdr))
			return TEE_ERROR_BAD_FORMAT;

		parse_ehdr(e_info, ehdr, true);
		if (e_info->elf_hdr_len != sizeof(*ehdr) ||
		    e_info->phdr_offset != e_info->elf_hdr_len ||
		    e_info->phdr_entry_len != sizeof(Elf64_Phdr))
			return TEE_ERROR_BAD_FORMAT;
		break;
	}
	case ELFCLASS32: {
		const Elf32_Ehdr *ehdr = (const void *)fw;

		if (fw_size < sizeof(*ehdr))
			return TEE_ERROR_BAD_FORMAT;

		parse_ehdr(e_info, ehdr, false);
		if (e_info->elf_hdr_len != sizeof(*ehdr) ||
		    e_info->phdr_offset != e_info->elf_hdr_len ||
		    e_info->phdr_entry_len != sizeof(Elf32_Phdr))
			return TEE_ERROR_BAD_FORMAT;
		break;
	}
	default:
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_elf_image_range(const uint8_t *fw, const struct elf_info *e_info,
			       uint64_t *base, uint64_t *end)
{
	uint64_t min_paddr = UINT64_MAX;
	struct phdr_info p_info = { };
	uint64_t seg_end = 0;
	uint64_t max_end = 0;
	size_t i = 0;

	if (!fw || !e_info || !base || !end)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < e_info->phdr_count; i++) {
		pas_elf_get_phdr(fw, e_info, i, &p_info);

		if (!pas_elf_is_hashed(p_info.type, p_info.flags))
			continue;

		if (ADD_OVERFLOW(p_info.paddr, p_info.mem_len, &seg_end))
			return TEE_ERROR_BAD_FORMAT;

		if (p_info.paddr < min_paddr)
			min_paddr = p_info.paddr;
		if (seg_end > max_end)
			max_end = seg_end;
	}

	if (min_paddr == UINT64_MAX)
		return TEE_ERROR_BAD_FORMAT;

	*base = ROUNDDOWN(min_paddr, SMALL_PAGE_SIZE);
	if (ROUNDUP_OVERFLOW(max_end, SMALL_PAGE_SIZE, end))
		return TEE_ERROR_BAD_FORMAT;

	return TEE_SUCCESS;
}
