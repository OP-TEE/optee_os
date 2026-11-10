// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "pas_iris.h"

/* Registers, as offsets from IRIS_BASE */
#define WRAPPER_TZ_XTSS_SW_RESET		0x000c1000
#define WRAPPER_XTSS_SW_RESET_BIT		BIT(0)
#define WRAPPER_TZ_SEC_CPA_START_ADDR		0x000c1020
#define WRAPPER_TZ_SEC_CPA_END_ADDR		0x000c1024
#define WRAPPER_TZ_SEC_FW_START_ADDR		0x000c1028
#define WRAPPER_TZ_SEC_FW_END_ADDR		0x000c102c
#define WRAPPER_TZ_SEC_NONPIX_START_ADDR	0x000c1030
#define WRAPPER_TZ_SEC_NONPIX_END_ADDR		0x000c1034

/*
 * Content protection (CP) windows in the device address space of the core,
 * end exclusive: the CP window starts at 0 and holds the firmware, the CP
 * non-pixel window lies inside it, above the firmware. This is the layout
 * Linux passes to the stock firmware for SC7280 and SM8550 (SA8775P).
 */
#define IRIS_CP_END			0x25800000
#define IRIS_CP_NONPIX_START		0x01000000
#define IRIS_CP_NONPIX_END		0x25800000

/* Largest seed accepted */
#define SEED_MAX_SIZE		SMALL_PAGE_SIZE
/* Each 32-bit word of a seed holds this until the seed is filled */
#define SEED_PLACEHOLDER	0xdeadd00d

/*
 * A Qualcomm video firmware image describes its seed with its last hashed
 * program header (newer images follow it with the hash segment): an image
 * segment of at most one page that the image fills with a placeholder. The
 * secure side fills it with random data after the image is loaded and
 * before the core starts, and refuses to start an image whose segment does
 * not hold the placeholder. An image without hashed segments has no seed.
 *
 * The seed belongs to one image of one subsystem: iris_find_seed() sets it
 * from that image's metadata and iris_fill_seed() consumes it, so a later
 * start never uses the location of an earlier image.
 */
static void iris_clear_seed(struct pas_iris_data *iris)
{
	iris->seed = (struct pas_iris_seed){ };
}

static TEE_Result iris_find_seed(struct qcom_pas_data *data,
				 const struct pas_metadata *metadata,
				 const struct elf_info *e_info)
{
	struct pas_iris_data *iris = data->subsystem_data;
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	uint64_t offset = 0;
	size_t size = 0;
	size_t idx = 0;

	if (!iris)
		return TEE_ERROR_BAD_STATE;

	iris_clear_seed(iris);

	for (idx = e_info->phdr_count; idx; idx--) {
		res = pas_elf_seg_range(metadata->data, e_info, idx - 1,
					&offset, &size);
		if (res != TEE_ERROR_ITEM_NOT_FOUND)
			break;
	}
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		iris->seed.valid = true;
		return TEE_SUCCESS;
	}
	if (res)
		return res;

	if (!size || size > SEED_MAX_SIZE ||
	    !IS_ALIGNED(size, sizeof(uint32_t))) {
		EMSG("Iris: last hashed segment of %#zx bytes is not a seed",
		     size);
		return TEE_ERROR_BAD_FORMAT;
	}

	iris->seed.offset = offset;
	iris->seed.size = size;
	iris->seed.valid = true;

	return TEE_SUCCESS;
}

static bool iris_seed_is_placeholder(const uint32_t *seed, size_t size)
{
	size_t n = 0;

	for (n = 0; n < size / sizeof(*seed); n++)
		if (seed[n] != SEED_PLACEHOLDER)
			return false;

	return true;
}

/*
 * Check that the seed of the loaded image holds the placeholder, fill it
 * with random data and write it to memory, where the core reads it,
 * through an existing mapping of the firmware region or one added and
 * removed here. The seed is consumed.
 */
static TEE_Result iris_fill_seed(struct qcom_pas_data *data,
				 struct pas_iris_data *iris)
{
	struct pas_iris_seed s = iris->seed;
	TEE_Result cache_res = TEE_ERROR_GENERIC;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool mapped = false;
	paddr_t pa = 0;
	size_t end = 0;
	void *va = NULL;

	iris_clear_seed(iris);

	if (!s.valid)
		return TEE_ERROR_BAD_STATE;

	if (!s.size)
		return TEE_SUCCESS;

	if (ADD_OVERFLOW(s.offset, s.size, &end) || end > data->fw_size ||
	    ADD_OVERFLOW(data->fw_base, s.offset, &pa) ||
	    !IS_ALIGNED(pa, sizeof(uint32_t)) ||
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

	/*
	 * Linux loads the image through a non-cacheable mapping: drop any
	 * line an earlier fill left before reading, and leave none behind,
	 * whatever the outcome
	 */
	res = cache_op_inner(DCACHE_AREA_INVALIDATE, va, s.size);
	if (!res && !iris_seed_is_placeholder(va, s.size)) {
		EMSG("Iris: seed at %#"PRIx64" is not the placeholder",
		     s.offset);
		res = TEE_ERROR_SECURITY;
	}
	if (!res)
		res = crypto_rng_read(va, s.size);
	cache_res = cache_op_inner(DCACHE_AREA_CLEAN_INV, va, s.size);
	if (!res)
		res = cache_res;

	if (mapped && core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, va, s.size)) {
		EMSG("Failed to unmap the video firmware seed");
		if (!res)
			res = TEE_ERROR_GENERIC;
	}

	return res;
}

/* The firmware must fit below the CP non-pixel window */
static TEE_Result iris_check_fw_size(struct qcom_pas_data *data)
{
	if (!data->fw_size || data->fw_size > IRIS_CP_NONPIX_START) {
		EMSG("Iris: firmware size %#zx outside the CP layout",
		     data->fw_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void iris_program_mem_regions(vaddr_t base,
				     const struct qcom_pas_data *data)
{
	io_write32(base + WRAPPER_TZ_SEC_FW_START_ADDR, 0);
	io_write32(base + WRAPPER_TZ_SEC_FW_END_ADDR, data->fw_size);
	io_write32(base + WRAPPER_TZ_SEC_CPA_START_ADDR, 0);
	io_write32(base + WRAPPER_TZ_SEC_CPA_END_ADDR, IRIS_CP_END);
	io_write32(base + WRAPPER_TZ_SEC_NONPIX_START_ADDR,
		   IRIS_CP_NONPIX_START);
	io_write32(base + WRAPPER_TZ_SEC_NONPIX_END_ADDR, IRIS_CP_NONPIX_END);
}

static TEE_Result iris_reset_cpu(struct qcom_pas_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = 0;

	res = iris_check_fw_size(data);
	if (res)
		return res;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	iris_program_mem_regions(base, data);
	io_write32(base + WRAPPER_TZ_XTSS_SW_RESET, 0);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_shutdown(struct qcom_pas_data *data)
{
	vaddr_t base = 0;
	uint32_t reg = 0;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	reg = io_read32(base + WRAPPER_TZ_XTSS_SW_RESET);
	reg |= WRAPPER_XTSS_SW_RESET_BIT;
	io_write32(base + WRAPPER_TZ_XTSS_SW_RESET, reg);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	struct pas_iris_data *iris = data->subsystem_data;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!iris)
		return TEE_ERROR_BAD_STATE;

	res = iris_check_fw_size(data);
	if (res) {
		iris_clear_seed(iris);
		return res;
	}

	res = iris_fill_seed(data, iris);
	if (res) {
		EMSG("Iris: cannot fill the firmware seed: %#"PRIx32, res);
		return res;
	}

	return iris_reset_cpu(data);
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	if (power_on)
		return iris_reset_cpu(data);

	return iris_fw_shutdown(data);
}

const struct qcom_pas_ops pas_iris_ops = {
	.fw_init_image = iris_find_seed,
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
