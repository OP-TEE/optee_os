// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <pas_init.h>
#include <elf32.h>
#include <elf64.h>
#include <util.h>

/* Segment type lives in bits 24:26 of p_flags; 0x2 marks the hash segment. */
#define MBN_PT_FLAG_TYPE_MASK           0x07000000U
#define MBN_PT_FLAG_HASH_TYPE_MASK      0x02000000U
#define PAS_ALIGN_4K                    4096ULL
#define PT_LOAD                         1

static bool pas_mbn_phdr_loadable(uint32_t p_type, uint32_t p_flags,
				  uint64_t p_memsz)
{
	if (p_type != PT_LOAD)
		return false;

	if ((p_flags & MBN_PT_FLAG_TYPE_MASK) == MBN_PT_FLAG_HASH_TYPE_MASK)
		return false;

	if (!p_memsz)
		return false;

	return true;
}

static TEE_Result pas_mbn_scan_phdrs_32(const uint8_t *metadata,
					size_t metadata_size,
					const Elf32_Ehdr *ehdr,
					uint64_t *min_addr,
					uint64_t *max_addr)
{
	size_t phdr_table_size = 0;
	size_t phdr_table_end = 0;
	size_t i = 0;
	bool found = false;

	if (ehdr->e_phentsize != sizeof(Elf32_Phdr) || !ehdr->e_phnum ||
	    ehdr->e_phoff != sizeof(*ehdr))
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW((size_t)ehdr->e_phnum, sizeof(Elf32_Phdr),
			 &phdr_table_size) ||
	    ADD_OVERFLOW((size_t)ehdr->e_phoff, phdr_table_size,
			 &phdr_table_end) ||
	    phdr_table_end > metadata_size)
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < ehdr->e_phnum; i++) {
		const Elf32_Phdr *phdr = (const void *)(metadata + ehdr->e_phoff
							+ i * sizeof(*phdr));
		uint64_t start = phdr->p_paddr;
		uint64_t end = 0;
		uint64_t aligned_end = 0;

		if (!pas_mbn_phdr_loadable(phdr->p_type, phdr->p_flags,
					   phdr->p_memsz))
			continue;

		if (ADD_OVERFLOW(start, (uint64_t)phdr->p_memsz, &end) ||
		    ADD_OVERFLOW(end, PAS_ALIGN_4K - 1, &aligned_end))
			return TEE_ERROR_BAD_FORMAT;

		aligned_end &= ~(PAS_ALIGN_4K - 1);

		if (start < *min_addr)
			*min_addr = start;
		if (aligned_end > *max_addr)
			*max_addr = aligned_end;

		found = true;
	}

	return found ? TEE_SUCCESS : TEE_ERROR_BAD_FORMAT;
}

static TEE_Result pas_mbn_scan_phdrs_64(const uint8_t *metadata,
					size_t metadata_size,
					const Elf64_Ehdr *ehdr,
					uint64_t *min_addr,
					uint64_t *max_addr)
{
	size_t phdr_table_size = 0;
	size_t phdr_table_end = 0;
	size_t i = 0;
	bool found = false;

	if (ehdr->e_phentsize != sizeof(Elf64_Phdr) || !ehdr->e_phnum ||
	    ehdr->e_phoff != sizeof(*ehdr))
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW((size_t)ehdr->e_phnum, sizeof(Elf64_Phdr),
			 &phdr_table_size) ||
	    ADD_OVERFLOW((size_t)ehdr->e_phoff, phdr_table_size,
			 &phdr_table_end) ||
	    phdr_table_end > metadata_size)
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < ehdr->e_phnum; i++) {
		const Elf64_Phdr *phdr = (const void *)(metadata + ehdr->e_phoff
							+ i * sizeof(*phdr));
		uint64_t start = phdr->p_paddr;
		uint64_t end = 0;
		uint64_t aligned_end = 0;

		if (!pas_mbn_phdr_loadable(phdr->p_type, phdr->p_flags,
					   phdr->p_memsz))
			continue;

		if (ADD_OVERFLOW(start, phdr->p_memsz, &end) ||
		    ADD_OVERFLOW(end, PAS_ALIGN_4K - 1, &aligned_end))
			return TEE_ERROR_BAD_FORMAT;

		aligned_end &= ~(PAS_ALIGN_4K - 1);

		if (start < *min_addr)
			*min_addr = start;
		if (aligned_end > *max_addr)
			*max_addr = aligned_end;

		found = true;
	}

	return found ? TEE_SUCCESS : TEE_ERROR_BAD_FORMAT;
}

TEE_Result pas_get_fw_min_max_addr(const uint8_t *metadata,
				   size_t metadata_size,
				   uint64_t *min_addr, uint64_t *max_addr)
{
	const unsigned char *ident = metadata;

	if (!metadata || !metadata_size || !min_addr || !max_addr)
		return TEE_ERROR_BAD_PARAMETERS;

	if (metadata_size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
		return TEE_ERROR_BAD_FORMAT;

	*min_addr = UINT64_MAX;
	*max_addr = 0;

	switch (ident[EI_CLASS]) {
	case ELFCLASS64: {
		const Elf64_Ehdr *ehdr = (const void *)metadata;

		if (metadata_size < sizeof(*ehdr))
			return TEE_ERROR_BAD_FORMAT;

		if (pas_mbn_scan_phdrs_64(metadata, metadata_size,
					  ehdr, min_addr, max_addr))
			return TEE_ERROR_BAD_FORMAT;
		break;
	}
	case ELFCLASS32: {
		const Elf32_Ehdr *ehdr = (const void *)metadata;

		if (metadata_size < sizeof(*ehdr))
			return TEE_ERROR_BAD_FORMAT;

		if (pas_mbn_scan_phdrs_32(metadata, metadata_size,
					  ehdr, min_addr, max_addr))
			return TEE_ERROR_BAD_FORMAT;
		break;
	}
	default:
		return TEE_ERROR_BAD_FORMAT;
	}

	if (*min_addr >= *max_addr)
		return TEE_ERROR_BAD_FORMAT;

	return TEE_SUCCESS;
}
