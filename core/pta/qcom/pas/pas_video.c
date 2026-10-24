// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_pas.h>
#include <trace.h>
#include <util.h>

#include "pas_video.h"

/* Largest seed accepted */
#define SEED_MAX_SIZE	SMALL_PAGE_SIZE

TEE_Result pas_video_find_seed(const uint8_t *metadata,
			       const struct elf_info *e_info,
			       struct pas_video_seed *seed)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint64_t offset = 0;
	size_t size = 0;

	pas_video_clear_seed(seed);

	res = pas_elf_seg_range(metadata, e_info, e_info->phdr_count - 1,
				&offset, &size);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		seed->valid = true;
		return TEE_SUCCESS;
	}
	if (res)
		return res;

	if (size > SEED_MAX_SIZE)
		return TEE_ERROR_BAD_FORMAT;

	seed->offset = offset;
	seed->size = size;
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
