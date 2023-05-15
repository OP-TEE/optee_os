// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
 */

#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>

/*
 * tee_uta_cache_operation - dynamic cache clean/inval request from a TA.
 * It follows ARM recommendation:
 *     https://developer.arm.com/documentation/ddi0246/c/Beicdhde
 * Note that this implementation assumes dsb operations are part of
 * cache_op_inner(), and outer cache sync are part of cache_op_outer().
 */
TEE_Result cache_operation(enum utee_cache_operation op, void *va, size_t len)
{
	TEE_Result res;
	paddr_t pa;

	pa = virt_to_phys(va);
	if (!pa)
		return TEE_ERROR_ACCESS_DENIED;

	switch (op) {
	case TEE_CACHEFLUSH:
#ifdef CFG_PL310 /* prevent initial L1 clean in case there is no outer L2 */
		/* Clean L1, Flush L2, Flush L1 */
		res = cache_op_inner(DCACHE_AREA_CLEAN, va, len);
		if (res != TEE_SUCCESS)
			return res;
		res = cache_op_outer(DCACHE_AREA_CLEAN_INV, pa, len);
		if (res != TEE_SUCCESS)
			return res;
#endif
		return cache_op_inner(DCACHE_AREA_CLEAN_INV, va, len);

	case TEE_CACHECLEAN:
		/* Clean L1, Clean L2 */
		res = cache_op_inner(DCACHE_AREA_CLEAN, va, len);
		if (res != TEE_SUCCESS)
			return res;
		return cache_op_outer(DCACHE_AREA_CLEAN, pa, len);

	case TEE_CACHEINVALIDATE:
		/* Inval L2, Inval L1 */
		res = cache_op_outer(DCACHE_AREA_INVALIDATE, pa, len);
		if (res != TEE_SUCCESS)
			return res;
		return cache_op_inner(DCACHE_AREA_INVALIDATE, va, len);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
