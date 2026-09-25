// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#include <io.h>
#include <trace.h>
#include <mm/core_mmu.h>
#include <pta_invoke_tests.h>
#include <riscv_pmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#include "misc.h"

static const uint32_t rodata_pattern = 0x5a5aa5a5;
static uint32_t rwdata_scratch;

static bool core_va_attr(vaddr_t va, uint32_t *attr)
{
	struct core_mmu_table_info tbl = { };

	if (!core_mmu_find_table(NULL, va, UINT_MAX, &tbl))
		return false;

	core_mmu_get_entry(&tbl, core_mmu_va2idx(&tbl, va), NULL, attr);

	return true;
}

/*
 * A page that is not mapped grants less than the PMP entry does, which is
 * safe: core memory that was handed back, such as the unused tail of the
 * boot allocator, leaves holes in the region.
 */
static bool va_attr_matches(vaddr_t va, uint8_t perms)
{
	uint32_t attr = 0;

	if (!core_va_attr(va, &attr) || !(attr & TEE_MATTR_VALID_BLOCK))
		return true;

	if ((attr & TEE_MATTR_PW) && !(perms & RISCV_PMP_W))
		return false;

	if ((attr & TEE_MATTR_PX) && !(perms & RISCV_PMP_X))
		return false;

	/* Core memory is never reachable from user mode */
	return !(attr & (TEE_MATTR_UR | TEE_MATTR_UW | TEE_MATTR_UX));
}

/*
 * No page of a region may grant more than the region's PMP entry does.
 * Every page is checked since one stray writable page in the read-execute
 * region undoes what the split is for.
 */
static bool region_attr_matches(const struct riscv_pmp_region *r)
{
	size_t offs = 0;

	for (offs = 0; offs < riscv_pmp_region_size(r);
	     offs += SMALL_PAGE_SIZE) {
		uint32_t attr = 0;

		if (!va_attr_matches(r->va + offs, r->perms)) {
			core_va_attr(r->va + offs, &attr);
			DMSG("%s +%#zx va %#"PRIxVA" attr %#"PRIx32" perms %#x",
			     r->name, offs, r->va + offs, attr, r->perms);
			return false;
		}
	}

	return true;
}

static bool regions_are_separate(const struct riscv_pmp_region *r, size_t count)
{
	size_t n = 0;

	for (n = 0; n < count; n++) {
		if (!riscv_pmp_region_is_napot(r + n))
			return false;

		/* Laid out back to back, so this is what rules out overlap */
		if (n && r[n].base != r[n - 1].base +
		    riscv_pmp_region_size(r + n - 1))
			return false;
	}

	return true;
}

static bool permitted_accesses_work(void)
{
	/* An all zero word is not a valid instruction, so this cannot be one */
	if (!io_read32((vaddr_t)permitted_accesses_work))
		return false;

	if (rodata_pattern != 0x5a5aa5a5)
		return false;

	rwdata_scratch = 0;
	rwdata_scratch = rodata_pattern;

	return rwdata_scratch == rodata_pattern;
}

TEE_Result core_pmp_tests(uint32_t param_types,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct riscv_pmp_region region[RISCV_PMP_CORE_REGION_COUNT] = { };
	uint32_t flags = 0;
	size_t count = 0;
	size_t n = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = 0;
	params[0].value.b = 0;

	flags |= PTA_INVOKE_TESTS_REGIONS_ENABLED;

	count = riscv_pmp_core_regions(region, ARRAY_SIZE(region));
	if (count == RISCV_PMP_CORE_REGION_COUNT) {
		if (regions_are_separate(region, count))
			flags |= PTA_INVOKE_TESTS_REGIONS_NAPOT;

		for (n = 0; n < count; n++)
			if (!region_attr_matches(region + n))
				break;
		if (n == count)
			flags |= PTA_INVOKE_TESTS_REGIONS_PERMS;

		if (permitted_accesses_work())
			flags |= PTA_INVOKE_TESTS_REGIONS_ACCESS;
	}

	params[0].value.a = flags;
	params[0].value.b = count;

	return TEE_SUCCESS;
}
