/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>

/*
 * tee_uta_cache_operation - dynamic cache clean/inval request from a TA.
 * It follows ARM recommendation:
 *     http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0246d/Beicdhde.html
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
