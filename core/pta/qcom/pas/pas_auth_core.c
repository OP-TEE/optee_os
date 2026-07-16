// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <elf32.h>
#include <elf64.h>
#include <mm/core_mmu.h>
#include <pas_auth_core.h>
#include <platform_pas.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#include "pas_subsys.h"

/*
 * Bounds check computed in uint64_t so a 64-bit ELF offset/size never narrows
 * on the way in (size_t arguments widen safely). Rejects wrap in off + len and
 * requires the result to fit within total.
 */
static bool range_ok(uint64_t off, uint64_t len, uint64_t total)
{
	uint64_t end = 0;

	if (ADD_OVERFLOW(off, len, &end))
		return false;

	return end <= total;
}

/*
 * Qualcomm program-header flags encode segment type and access type.
 * QCOM_MDT_RELOCATABLE (bit 27) marks a relocatable image.
 */
#define MI_PBT_PAGE_MODE_MASK		0x00100000
#define MI_PBT_PAGE_MODE_SHIFT		20
#define MI_PBT_ACCESS_TYPE_MASK		0x00E00000
#define MI_PBT_ACCESS_TYPE_SHIFT	21
#define MI_PBT_SEGMENT_TYPE_MASK	0x07000000
#define MI_PBT_SEGMENT_TYPE_SHIFT	24

#define MI_PBT_NON_PAGED_SEGMENT	0x0
#define MI_PBT_HASH_SEGMENT		0x2
/*
 * NOTUSED/SHARED are access-type field values (not segment-type values); the
 * MI_PBT_*_SEGMENT naming follows the reference program-header definitions.
 */
#define MI_PBT_NOTUSED_SEGMENT		0x3
#define MI_PBT_SHARED_SEGMENT		0x4

#define QCOM_MDT_RELOCATABLE		BIT(27)

#define MI_PBT_PAGE_MODE(x) \
	(((x) & MI_PBT_PAGE_MODE_MASK) >> MI_PBT_PAGE_MODE_SHIFT)
#define MI_PBT_ACCESS_TYPE(x) \
	(((x) & MI_PBT_ACCESS_TYPE_MASK) >> MI_PBT_ACCESS_TYPE_SHIFT)
#define MI_PBT_SEGMENT_TYPE(x) \
	(((x) & MI_PBT_SEGMENT_TYPE_MASK) >> MI_PBT_SEGMENT_TYPE_SHIFT)

static bool is_hashed(uint32_t p_type, uint32_t p_flags)
{
	if (p_type != PT_LOAD)
		return false;

	return MI_PBT_PAGE_MODE(p_flags) == MI_PBT_NON_PAGED_SEGMENT &&
	       MI_PBT_SEGMENT_TYPE(p_flags) != MI_PBT_HASH_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_NOTUSED_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_SHARED_SEGMENT;
}

struct elf_info {
	size_t ehsize;
	size_t phoff;
	size_t phentsize;
	size_t phnum;
	bool is_64;
};

static TEE_Result parse_elf(const uint8_t *fw, size_t fw_size,
			    struct elf_info *info)
{
	const unsigned char *ident = fw;
	size_t ehdr_size = 0;
	size_t phent_size = 0;

	if (fw_size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
		return TEE_ERROR_BAD_FORMAT;

	switch (ident[EI_CLASS]) {
	case ELFCLASS64:
		info->is_64 = true;
		ehdr_size = sizeof(Elf64_Ehdr);
		phent_size = sizeof(Elf64_Phdr);
		break;
	case ELFCLASS32:
		info->is_64 = false;
		ehdr_size = sizeof(Elf32_Ehdr);
		phent_size = sizeof(Elf32_Phdr);
		break;
	default:
		return TEE_ERROR_BAD_FORMAT;
	}

	if (fw_size < ehdr_size)
		return TEE_ERROR_BAD_FORMAT;

	/* Elf32_Ehdr and Elf64_Ehdr name these header fields identically. */
	if (info->is_64) {
		const Elf64_Ehdr *ehdr = (const void *)fw;

		info->ehsize = ehdr->e_ehsize;
		info->phoff = ehdr->e_phoff;
		info->phentsize = ehdr->e_phentsize;
		info->phnum = ehdr->e_phnum;
	} else {
		const Elf32_Ehdr *ehdr = (const void *)fw;

		info->ehsize = ehdr->e_ehsize;
		info->phoff = ehdr->e_phoff;
		info->phentsize = ehdr->e_phentsize;
		info->phnum = ehdr->e_phnum;
	}

	if (info->phentsize < phent_size)
		return TEE_ERROR_BAD_FORMAT;

	return TEE_SUCCESS;
}

static void get_phdr(const uint8_t *fw, const struct elf_info *info,
		     size_t idx, uint32_t *p_type, uint32_t *p_flags,
		     uint64_t *p_paddr, size_t *p_filesz, size_t *p_memsz)
{
	const uint8_t *p = fw + info->phoff + idx * info->phentsize;

	/* Elf32_Phdr and Elf64_Phdr name these fields identically. */
	if (info->is_64) {
		const Elf64_Phdr *phdr = (const void *)p;

		*p_type = phdr->p_type;
		*p_flags = phdr->p_flags;
		*p_paddr = phdr->p_paddr;
		*p_filesz = phdr->p_filesz;
		*p_memsz = phdr->p_memsz;
	} else {
		const Elf32_Phdr *phdr = (const void *)p;

		*p_type = phdr->p_type;
		*p_flags = phdr->p_flags;
		*p_paddr = phdr->p_paddr;
		*p_filesz = phdr->p_filesz;
		*p_memsz = phdr->p_memsz;
	}
}

/*
 * Loader predicate matching the kernel MDT loader's mdt_phdr_loadable(): a
 * segment contributes to the relocation base only if it is PT_LOAD, not the
 * hash segment, and has a nonzero memory size. This is deliberately distinct
 * from is_hashed() (the hashing filter, which also excludes paged/NOTUSED/
 * SHARED segments): the relocation base must be computed over exactly the set
 * the kernel loader used to place the segments.
 */
static bool mdt_loadable(uint32_t p_type, uint32_t p_flags, size_t p_memsz)
{
	return p_type == PT_LOAD &&
	       MI_PBT_SEGMENT_TYPE(p_flags) != MI_PBT_HASH_SEGMENT &&
	       p_memsz != 0;
}

/*
 * Mirror qcom_mdt_load_no_init(): if any loadable phdr has the RELOCATABLE
 * bit, segments are placed from min(paddr) over the loadable set; otherwise
 * from fw_phys.
 */
static uint64_t reloc_base(const uint8_t *fw, const struct elf_info *info,
			   paddr_t fw_phys)
{
	uint64_t min_paddr = UINT64_MAX;
	bool relocatable = false;
	uint64_t paddr = 0;
	uint32_t flags = 0;
	uint32_t type = 0;
	size_t filesz = 0;
	size_t memsz = 0;
	size_t i = 0;

	for (i = 0; i < info->phnum; i++) {
		get_phdr(fw, info, i, &type, &flags, &paddr, &filesz, &memsz);

		if (!mdt_loadable(type, flags, memsz))
			continue;

		if (flags & QCOM_MDT_RELOCATABLE)
			relocatable = true;

		if (paddr < min_paddr)
			min_paddr = paddr;
	}

	if (relocatable && min_paddr != UINT64_MAX)
		return min_paddr;

	return fw_phys;
}

static TEE_Result hash_verify(uint32_t algo, const uint8_t *data,
			      size_t data_len, const uint8_t *expected,
			      size_t hash_size)
{
	uint8_t dgst[PAS_AUTH_CORE_MAX_HASH_SIZE] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (hash_size > sizeof(dgst))
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_createdigest(algo, data, data_len, dgst, hash_size);
	if (res)
		return res;

	if (consttime_memcmp(dgst, expected, hash_size))
		res = TEE_ERROR_SECURITY;
	else
		res = TEE_SUCCESS;

	memzero_explicit(dgst, sizeof(dgst));

	return res;
}

static TEE_Result verify_elf_header(const struct pas_auth_core_ctx *ctx,
				    const struct elf_info *info)
{
	size_t hdr_len = 0;

	/* Program-header table size: phentsize * phnum. */
	if (MUL_OVERFLOW(info->phentsize, info->phnum, &hdr_len))
		return TEE_ERROR_BAD_FORMAT;

	/* Entry-0 covers the ELF header followed by that table. */
	if (ADD_OVERFLOW(hdr_len, info->ehsize, &hdr_len))
		return TEE_ERROR_BAD_FORMAT;

	/* The covered range must fit within the metadata blob. */
	if (hdr_len > ctx->metadata_size)
		return TEE_ERROR_BAD_FORMAT;

	return hash_verify(ctx->hash_algo, ctx->metadata, hdr_len,
			   ctx->hash_table, ctx->hash_size);
}

TEE_Result pas_auth_core_verify_segments(const struct pas_auth_core_ctx *ctx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *expected = NULL;
	struct elf_info info = { };
	size_t phtab_size = 0;
	uint64_t paddr = 0;
	uint32_t flags = 0;
	uint64_t offset = 0;
	uint32_t type = 0;
	size_t filesz = 0;
	size_t memsz = 0;
	size_t verified = 0;
	uint64_t base = 0;
	size_t i = 0;

	if (!ctx || !ctx->hash_table || !ctx->fw || !ctx->metadata)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!ctx->hash_size || ctx->hash_size > PAS_AUTH_CORE_MAX_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Parse the ELF from the metadata blob (ELF header + phdrs + hash seg),
	 * NOT from the carveout. The carveout holds only the loaded segments;
	 * the ELF header is not placed there by the MDT loader.
	 */
	res = parse_elf(ctx->metadata, ctx->metadata_size, &info);
	if (res)
		return res;

	if (MUL_OVERFLOW(info.phentsize, info.phnum, &phtab_size) ||
	    !range_ok(info.phoff, phtab_size, ctx->metadata_size))
		return TEE_ERROR_BAD_FORMAT;

	if (ctx->num_entries != info.phnum)
		return TEE_ERROR_SECURITY;

	/* Entry 0: hash of ELF header + phdr table from metadata */
	res = verify_elf_header(ctx, &info);
	if (res) {
		EMSG("PAS auth: ELF header hash mismatch");
		return res;
	}

	/* Reloc base: for relocatable images = min(paddr); else = fw_phys */
	base = reloc_base(ctx->metadata, &info, ctx->fw_phys);

	for (i = 0; i < info.phnum; i++) {
		get_phdr(ctx->metadata, &info, i, &type, &flags, &paddr,
			 &filesz, &memsz);

		if (!is_hashed(type, flags) || !filesz)
			continue;

		if (paddr < base)
			return TEE_ERROR_BAD_FORMAT;
		offset = paddr - base;

		if (!range_ok(offset, filesz, ctx->fw_size))
			return TEE_ERROR_BAD_FORMAT;

		expected = ctx->hash_table + i * ctx->hash_size;

		res = hash_verify(ctx->hash_algo, ctx->fw + offset, filesz,
				  expected, ctx->hash_size);
		if (res) {
			EMSG("PAS auth: segment %zu hash mismatch", i);
			return res;
		}

		verified++;
	}

	DMSG("PAS auth: ELF header + %zu segment(s) verified", verified);

	return TEE_SUCCESS;
}

TEE_Result pas_platform_verify_image(uint32_t pas_id, uint32_t fw_size,
				     paddr_t fw_base, const uint8_t *metadata,
				     size_t metadata_size,
				     const uint8_t *hash_table,
				     size_t table_len, uint32_t hash_size)
{
	struct qcom_pas_subsys *subsys = pas_lookup(pas_id);
	struct pas_auth_core_ctx ctx = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	struct qcom_pas_data *data = NULL;
	void *fw_va = NULL;

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!metadata || !metadata_size || !hash_table ||
	    !table_len || !fw_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hash_size || table_len % hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	data = &subsys->data;
	DMSG("PAS verify: pas_id=%"PRIu32" arg=%#"PRIxPA"/%#"PRIx32
	     " setup=%#"PRIxPA"/%#zx",
	     pas_id, fw_base, fw_size, data->fw_base, data->fw_size);

	/*
	 * Prefer the base/size from MEM_SETUP: AUTH_AND_RESET passes the DTS
	 * carveout size which may be larger than the image span used during
	 * MEM_SETUP; use the image span for segment offset bounds checking.
	 */
	if (data->fw_base && data->fw_size) {
		if (fw_base != data->fw_base) {
			EMSG("PAS auth: base %#"PRIxPA" != MEM_SETUP %#"PRIxPA,
			     fw_base, data->fw_base);
			return TEE_ERROR_SECURITY;
		}
		fw_size = data->fw_size; /* use image span for verification */
	} else if (!fw_base || !fw_size) {
		EMSG("PAS auth: no fw_base/size, no MEM_SETUP pas_id=%"PRIu32,
		     pas_id);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Map the non-secure firmware carveout to recompute its digests */
	fw_va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, fw_base, fw_size);
	if (!fw_va) {
		EMSG("PAS auth: can't map carveout %#"PRIxPA"/%#"PRIx32,
		     fw_base, fw_size);
		return TEE_ERROR_GENERIC;
	}

	switch (hash_size) {
	case TEE_SHA256_HASH_SIZE:
		ctx.hash_algo = TEE_ALG_SHA256;
		break;
	case TEE_SHA384_HASH_SIZE:
		ctx.hash_algo = TEE_ALG_SHA384;
		break;
	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ctx.hash_size = hash_size;
	ctx.hash_table = hash_table;
	ctx.num_entries = table_len / hash_size;
	ctx.metadata = metadata;
	ctx.metadata_size = metadata_size;
	ctx.fw = fw_va;
	ctx.fw_size = fw_size;
	ctx.fw_phys = fw_base;

	res = pas_auth_core_verify_segments(&ctx);
out:
	if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, fw_va, fw_size))
		EMSG("PAS auth: failed to unmap carveout");

	return res;
}
