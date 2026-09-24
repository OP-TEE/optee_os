// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RiscStar
 */

#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>

TEE_Result cache_operation(enum utee_cache_operation op, void *va, size_t len)
{
	if (!virt_to_phys(va))
		return TEE_ERROR_ACCESS_DENIED;

	switch (op) {
	case TEE_CACHEFLUSH:
		return cache_op_inner(DCACHE_AREA_CLEAN_INV, va, len);
	case TEE_CACHECLEAN:
		return cache_op_inner(DCACHE_AREA_CLEAN, va, len);
	case TEE_CACHEINVALIDATE:
		return cache_op_inner(DCACHE_AREA_INVALIDATE, va, len);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
