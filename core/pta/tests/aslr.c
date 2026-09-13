// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RiscStar
 */

#include <config.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <pta_invoke_tests.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

#include "misc.h"

/*
 * Only unpaged memory keeps a fixed relation to its physical address, the
 * pager maps the rest to arbitrary physical pages.
 */
static bool va_pa_is_consistent(vaddr_t va, vaddr_t offs)
{
	paddr_t pa = 0;

	if (!is_unpaged((void *)va))
		return true;

	pa = virt_to_phys((void *)va);

	return pa && va - offs == pa;
}

TEE_Result core_aslr_tests(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	vaddr_t va = VCORE_START_VA;
	vaddr_t offs = boot_mmu_config.map_offset;
	uint32_t flags = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_CORE_ASLR))
		flags |= PTA_INVOKE_TESTS_ASLR_ENABLED;
	if (offs)
		flags |= PTA_INVOKE_TESTS_ASLR_RANDOMIZED;

	DMSG("core VA %#"PRIxVA" PA %#"PRIxPA" offset %#"PRIxVA,
	     va, virt_to_phys((void *)va), offs);

	params[0].value.a = flags;
	params[0].value.b = 0;

	if (!IS_ALIGNED(offs, SMALL_PAGE_SIZE))
		return TEE_ERROR_GENERIC;

	if (!va_pa_is_consistent(va, offs) ||
	    !va_pa_is_consistent((vaddr_t)core_aslr_tests, offs))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
