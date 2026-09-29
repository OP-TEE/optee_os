// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <elf32.h>
#include <elf64.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_pas.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#include "pas_subsys.h"

#define MAX_HASH_SIZE			48U

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

struct elf_info {
	size_t elf_hdr_len;
	size_t phdr_offset;
	size_t phdr_entry_len;
	size_t phdr_count;
	uint64_t entry;
	bool is_64;
};

struct phdr_info {
	uint64_t paddr;
	size_t file_len;
	size_t mem_len;
	uint32_t type;
	uint32_t flags;
};

struct verify_ctx {
	uint32_t hash_algo;
	size_t hash_len;
	const uint8_t *hash_table;
	uint32_t num_entries;
	const uint8_t *metadata;
	size_t metadata_len;
	uint8_t *fw;
	size_t fw_size;
};

#define PARSE_EHDR(e_info, ehdr, _is_64) do {				\
	(e_info)->is_64 = (_is_64);					\
	(e_info)->elf_hdr_len = (ehdr)->e_ehsize;			\
	(e_info)->phdr_offset = (ehdr)->e_phoff;			\
	(e_info)->phdr_entry_len = (ehdr)->e_phentsize;		\
	(e_info)->phdr_count = (ehdr)->e_phnum;			\
	(e_info)->entry = (ehdr)->e_entry;			\
} while (0)

#define PARSE_PHDR(p_info, phdr) do {					\
	(p_info)->paddr = (phdr)->p_paddr;				\
	(p_info)->file_len = (phdr)->p_filesz;				\
	(p_info)->mem_len = (phdr)->p_memsz;				\
	(p_info)->type = (phdr)->p_type;				\
	(p_info)->flags = (phdr)->p_flags;				\
} while (0)

static bool check_range(uint64_t off, uint64_t len, uint64_t total)
{
	uint64_t end = 0;

	if (ADD_OVERFLOW(off, len, &end))
		return false;

	return end <= total;
}

static bool is_hashed(uint32_t p_type, uint32_t p_flags)
{
	if (p_type != PT_LOAD)
		return false;

	return MI_PBT_PAGE_MODE(p_flags) == MI_PBT_NON_PAGED_SEGMENT &&
	       MI_PBT_SEGMENT_TYPE(p_flags) != MI_PBT_HASH_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_NOTUSED_SEGMENT &&
	       MI_PBT_ACCESS_TYPE(p_flags) != MI_PBT_SHARED_SEGMENT;
}

static TEE_Result parse_elf(const uint8_t *fw, size_t fw_size,
			    struct elf_info *e_info)
{
	const unsigned char *ident = fw;

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

		PARSE_EHDR(e_info, ehdr, true);
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

		PARSE_EHDR(e_info, ehdr, false);
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

static void get_phdr(const uint8_t *fw, const struct elf_info *e_info,
		     size_t idx, struct phdr_info *p_info)
{
	const uint8_t *p = fw + e_info->phdr_offset +
			   idx * e_info->phdr_entry_len;

	if (e_info->is_64) {
		const Elf64_Phdr *phdr = (const void *)p;

		PARSE_PHDR(p_info, phdr);
	} else {
		const Elf32_Phdr *phdr = (const void *)p;

		PARSE_PHDR(p_info, phdr);
	}
}

static TEE_Result image_range(const uint8_t *fw, const struct elf_info *e_info,
			      uint64_t *base, uint64_t *end)
{
	uint64_t min_paddr = UINT64_MAX;
	struct phdr_info p_info = { };
	uint64_t seg_end = 0;
	uint64_t max_end = 0;
	size_t i = 0;

	for (i = 0; i < e_info->phdr_count; i++) {
		get_phdr(fw, e_info, i, &p_info);

		if (!is_hashed(p_info.type, p_info.flags))
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

static TEE_Result hash_verify(uint32_t algo, const uint8_t *data,
			      size_t data_len, const uint8_t *expected,
			      size_t hash_len)
{
	uint8_t digest[MAX_HASH_SIZE] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (hash_len > sizeof(digest))
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_createdigest(algo, data, data_len, digest, hash_len);
	if (res)
		return res;

	if (consttime_memcmp(digest, expected, hash_len))
		res = TEE_ERROR_SECURITY;
	else
		res = TEE_SUCCESS;

	memzero_explicit(digest, sizeof(digest));

	return res;
}

static TEE_Result verify_elf_header(const struct verify_ctx *ctx,
				    const struct elf_info *e_info)
{
	size_t hdr_len = 0;

	if (MUL_OVERFLOW(e_info->phdr_entry_len, e_info->phdr_count, &hdr_len))
		return TEE_ERROR_BAD_FORMAT;

	if (ADD_OVERFLOW(hdr_len, e_info->elf_hdr_len, &hdr_len))
		return TEE_ERROR_BAD_FORMAT;

	if (hdr_len > ctx->metadata_len)
		return TEE_ERROR_BAD_FORMAT;

	return hash_verify(ctx->hash_algo, ctx->metadata, hdr_len,
			   ctx->hash_table, ctx->hash_len);
}

static TEE_Result verify_segments(const struct verify_ctx *ctx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *expected = NULL;
	struct phdr_info p_info = { };
	struct elf_info e_info = { };
	size_t phdr_table_len = 0;
	uint64_t image_end = 0;
	uint64_t offset = 0;
	size_t verified = 0;
	uint64_t base = 0;
	size_t i = 0;

	if (!ctx || !ctx->hash_table || !ctx->fw || !ctx->metadata)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!ctx->hash_len || ctx->hash_len > MAX_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = parse_elf(ctx->metadata, ctx->metadata_len, &e_info);
	if (res)
		return res;

	if (MUL_OVERFLOW(e_info.phdr_entry_len, e_info.phdr_count,
			 &phdr_table_len) ||
	    !check_range(e_info.phdr_offset, phdr_table_len, ctx->metadata_len))
		return TEE_ERROR_BAD_FORMAT;

	if (ctx->num_entries != e_info.phdr_count)
		return TEE_ERROR_SECURITY;

	res = verify_elf_header(ctx, &e_info);
	if (res) {
		EMSG("PAS auth: ELF header hash mismatch");
		return res;
	}

	res = image_range(ctx->metadata, &e_info, &base, &image_end);
	if (res)
		return res;

	if (e_info.entry < base || e_info.entry > image_end) {
		EMSG("PAS auth: entry point outside image");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (image_end - base > ctx->fw_size) {
		EMSG("PAS auth: image larger than carveout");
		return TEE_ERROR_BAD_FORMAT;
	}

	for (i = 0; i < e_info.phdr_count; i++) {
		get_phdr(ctx->metadata, &e_info, i, &p_info);

		if (!is_hashed(p_info.type, p_info.flags) || !p_info.file_len)
			continue;

		if (p_info.paddr < base)
			return TEE_ERROR_BAD_FORMAT;
		offset = p_info.paddr - base;

		if (!check_range(offset, p_info.file_len, ctx->fw_size))
			return TEE_ERROR_BAD_FORMAT;

		if (p_info.mem_len < p_info.file_len)
			return TEE_ERROR_BAD_FORMAT;
		if (!check_range(offset, p_info.mem_len, ctx->fw_size))
			return TEE_ERROR_BAD_FORMAT;
		if (p_info.mem_len > p_info.file_len) {
			void *zi = ctx->fw + offset + p_info.file_len;
			size_t zi_len = p_info.mem_len - p_info.file_len;

			memset(zi, 0, zi_len);

			/*
			 * The REE maps this carveout uncached and the DSP
			 * fetches it outside the CPU's coherency domain, so the
			 * zeros must reach DDR before reset release.
			 */
			dcache_cleaninv_range(zi, zi_len);
		}

		expected = ctx->hash_table + i * ctx->hash_len;

		dcache_inv_range(ctx->fw + offset, p_info.file_len);

		res = hash_verify(ctx->hash_algo, ctx->fw + offset,
				  p_info.file_len, expected, ctx->hash_len);
		if (res) {
			EMSG("PAS auth: segment %zu hash mismatch", i);
			return res;
		}

		verified++;
	}

	if (!verified) {
		EMSG("PAS auth: no loadable segments were hashed");
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_platform_verify_image(uint32_t pas_id,
				     const struct pas_fw_region *fw,
				     const struct pas_metadata *metadata,
				     const struct pas_hash_table *hash)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);
	struct verify_ctx ctx = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	struct qcom_pas_data *data = NULL;
	uint32_t fw_size = 0;
	void *fw_va = NULL;

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!metadata->data || !metadata->size || !hash->table ||
	    !hash->len || !fw->size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hash->entry_size || hash->len % hash->entry_size)
		return TEE_ERROR_BAD_PARAMETERS;

	data = &subsys->data;

	if (!data->fw_base || !data->fw_size) {
		EMSG("PAS auth: no MEM_SETUP for pas_id=%#"PRIx32, pas_id);
		return TEE_ERROR_BAD_STATE;
	}

	if (fw->base != data->fw_base) {
		EMSG("PAS auth: base %#"PRIxPA" != MEM_SETUP %#"PRIxPA,
		     fw->base, data->fw_base);
		return TEE_ERROR_SECURITY;
	}
	fw_size = data->fw_size;

	if (!core_pbuf_is(CORE_MEM_NON_SEC, fw->base, fw_size)) {
		EMSG("PAS auth: carveout %#"PRIxPA"/%#"PRIx32" not non-secure",
		     fw->base, fw_size);
		return TEE_ERROR_SECURITY;
	}

	/*
	 * TOCTOU protection for the carveout is expected to come from
	 * the kernel's MMU/SMMU configuration.
	 */
	fw_va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, fw->base, fw_size);
	if (!fw_va) {
		EMSG("PAS auth: can't map carveout %#"PRIxPA"/%#"PRIx32,
		     fw->base, fw_size);
		return TEE_ERROR_GENERIC;
	}

	switch (hash->entry_size) {
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

	ctx.hash_len = hash->entry_size;
	ctx.hash_table = hash->table;
	ctx.num_entries = hash->len / hash->entry_size;
	ctx.metadata = metadata->data;
	ctx.metadata_len = metadata->size;
	ctx.fw = fw_va;
	ctx.fw_size = fw_size;

	res = verify_segments(&ctx);
out:
	if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, fw_va, fw_size))
		EMSG("PAS auth: failed to unmap carveout");

	return res;
}
