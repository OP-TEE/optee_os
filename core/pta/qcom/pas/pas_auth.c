// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

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

static bool check_range(uint64_t off, uint64_t len, uint64_t total)
{
	uint64_t end = 0;

	if (ADD_OVERFLOW(off, len, &end))
		return false;

	return end <= total;
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

	res = pas_elf_parse(ctx->metadata, ctx->metadata_len, &e_info);
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

	res = pas_elf_image_range(ctx->metadata, &e_info, &base, &image_end);
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
		pas_elf_get_phdr(ctx->metadata, &e_info, i, &p_info);

		if (!pas_elf_is_hashed(p_info.type, p_info.flags) ||
		    !p_info.file_len)
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
		EMSG("PAS auth: no fw base/size for pas_id=%#"PRIx32, pas_id);
		return TEE_ERROR_BAD_STATE;
	}

	if (fw->base != data->fw_base) {
		EMSG("PAS auth: carevout base %#"PRIxPA" != fw base %#"PRIxPA,
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
