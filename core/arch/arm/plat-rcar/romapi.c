// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, EPAM Systems
 */
#include <assert.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>

#include "rcar.h"
#include "romapi.h"

static int get_api_table_index(void)
{
	/*
	 * Depending on SoC type and version, there are 4 possible addresses
	 * for each ROMAPI function
	 */
	static int index __nex_data = -1;

	if (index != -1)
		return index;

	switch (rcar_prr_value & PRR_PRODUCT_MASK) {
	case PRR_PRODUCT_H3:
		switch (rcar_prr_value & PRR_CUT_MASK) {
		case PRR_CUT_10:	/* H3 ES1.0 */
		case PRR_CUT_11:	/* H3 ES1.1 */
			index = 0;
			break;
		case PRR_CUT_20:	/* H3 ES2.0 */
			index = 1;
			break;
		default:	/* Newer H3 versions use unified table */
			index = 3;
			break;
		}
		break;
	case PRR_PRODUCT_M3W:
		switch (rcar_prr_value & PRR_CUT_MASK) {
		case PRR_CUT_10:	/* M3 ES1.0 */
			index = 2;
			break;
		default:	/* Newer M3 versions use unified table */
			index = 3;
			break;
		}
		break;
	default:			/* All other SoCs use unified table */
		index = 3;
		break;
	}

	return index;
}

/* implemented in romapi_call.S */
extern uint32_t __plat_romapi_wrapper(paddr_t func, uint64_t arg1,
				      uint64_t arg2, uint64_t arg3);

static uint32_t __plat_romapi_direct(paddr_t func, uint64_t arg1,
				     uint64_t arg2, uint64_t arg3)
{
	uint32_t (*fptr)(uint64_t arg1, uint64_t arg2, uint64_t arg3) = NULL;

	assert(!cpu_mmu_enabled());

	fptr = (typeof(fptr))func;

	return fptr(arg1, arg2, arg3);
}

static uint32_t plat_call_romapi(paddr_t func, uint64_t arg1,
				 uint64_t arg2, uint64_t arg3)
{
	uint32_t (*fptr)(paddr_t func, uint64_t arg1, uint64_t arg2,
			 uint64_t arg3) = NULL;

	/*
	 * If MMU is enabled, we need to use trampoline function that will
	 * disable MMU and switch stack pointer to physical address. On other
	 * hand, if MMU is disabled, we can call the ROM function directly.
	 */
	if (cpu_mmu_enabled())
		/*
		 * With ASLR enabled __plat_romapi_wrapper() function will be
		 * mapped at two addresses: at random address (with the rest of
		 * OP-TEE) and at identity address. We need to map it at
		 * identity address and call it at identity address because this
		 * function turns off MMU to perform ROM API call. But
		 * __plat_romapi_wrapper *symbol* will be relocated by ASLR
		 * code. To get identity address of the function we need to use
		 * virt_to_phys().
		 */
		fptr = (void *)virt_to_phys(__plat_romapi_wrapper);
	else
		/*
		 * With MMU disabled we can call ROM code directly.
		 */
		fptr = __plat_romapi_direct;

	return fptr(func, arg1, arg2, arg3);
}

static paddr_t va2pa(void *ptr)
{
	if (cpu_mmu_enabled())
		return virt_to_phys(ptr);
	else
		return (paddr_t)ptr;
}

static const paddr_t romapi_getrndvector[] = {
	0xEB10DFC4,	/* H3 1.0/1.1, needs confirmation */
	0xEB117134,	/* H3 2.0 */
	0xEB11055C,	/* M3 1.0/1.05, needs confirmation */
	0xEB100188,	/* H3 3.0, M3 1.1+, M3N, E3, D3, V3M 2.0 */
};

uint32_t plat_rom_getrndvector(uint8_t rndbuff[PLAT_RND_VECTOR_SZ],
			       uint8_t *scratch, uint32_t scratch_sz)
{
	uint32_t ret = -1;
	paddr_t func_addr = romapi_getrndvector[get_api_table_index()];
	paddr_t rndbuff_pa = va2pa(rndbuff);
	paddr_t scratch_pa = va2pa(scratch);

	assert(scratch_sz >= 4096);
	assert(rndbuff_pa % RCAR_CACHE_LINE_SZ == 0);
	assert(scratch_pa % RCAR_CACHE_LINE_SZ == 0);

	ret = plat_call_romapi(func_addr, rndbuff_pa, scratch_pa, scratch_sz);

	/*
	 * ROM code is called with MMU turned off, so any accesses to rndbuff
	 * are not affected by data cache. This can lead to two problems:
	 *
	 * 1. Any prior writes can be cached but may not reach memory. So staled
	 * values can be flushed to memory later and overwrite new data written
	 * by ROM code. This includes stack as well.
	 *
	 * 2. ROM code will write new data to the buffer, but we may see old,
	 * cached values.
	 *
	 * ROM code wrapper will issue dcache_op_all(DCACHE_OP_CLEAN). This will
	 * ensure that all writes reached memory. After the call we need to
	 * invalidate the cache to see new data.
	 *
	 * We are not accessing scratch area, so no need to do cache maintenance
	 * for that buffer.
	 */
	cache_op_inner(DCACHE_AREA_INVALIDATE, rndbuff, PLAT_RND_VECTOR_SZ);

	return ret;
}
