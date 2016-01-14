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
#include <types_ext.h>
#include <utee_types.h>
#include <kernel/tee_ta_manager.h>
#include <mm/tee_mmu.h>
#include <mm/core_memprot.h>

#include "svc_cache.h"

/*
 * tee_uta_cache_operation - dynamic cache clean/inval request from a TA
 * It follows ARM recommendation:
 *     http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0246d/Beicdhde.html
 * Note that this implementation assumes dsb operations are part of
 * cache_maintenance_l1(), and L2 cache sync are part of
 * cache_maintenance_l2()
 */
static TEE_Result cache_operation(struct tee_ta_session *sess,
			enum utee_cache_operation op, void *va, size_t len)
{
	TEE_Result ret;
	paddr_t pa = 0;
	struct user_ta_ctx *utc = to_user_ta_ctx(sess->ctx);

	if ((sess->ctx->flags & TA_FLAG_CACHE_MAINTENANCE) == 0)
		return TEE_ERROR_NOT_SUPPORTED;

	ret = tee_mmu_check_access_rights(utc, TEE_MEMORY_ACCESS_WRITE,
					  (tee_uaddr_t)va, len);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_DENIED;

	pa = virt_to_phys(va);
	if (!pa)
		return TEE_ERROR_ACCESS_DENIED;

	switch (op) {
	case TEE_CACHEFLUSH:
		/* Clean L1, Flush L2, Flush L1 */
		ret = cache_maintenance_l1(DCACHE_AREA_CLEAN, va, len);
		if (ret != TEE_SUCCESS)
			return ret;
		ret = cache_maintenance_l2(L2CACHE_AREA_CLEAN_INV, pa, len);
		if (ret != TEE_SUCCESS)
			return ret;
		return cache_maintenance_l1(DCACHE_AREA_CLEAN_INV, va, len);

	case TEE_CACHECLEAN:
		/* Clean L1, Clean L2 */
		ret = cache_maintenance_l1(DCACHE_AREA_CLEAN, va, len);
		if (ret != TEE_SUCCESS)
			return ret;
		return cache_maintenance_l2(L2CACHE_AREA_CLEAN, pa, len);

	case TEE_CACHEINVALIDATE:
		/* Inval L2, Inval L1 */
		ret = cache_maintenance_l2(L2CACHE_AREA_INVALIDATE, pa, len);
		if (ret != TEE_SUCCESS)
			return ret;
		return cache_maintenance_l1(DCACHE_AREA_INVALIDATE, va, len);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result syscall_cache_operation(void *va, size_t len, unsigned long op)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	if ((s->ctx->flags & TA_FLAG_CACHE_MAINTENANCE) == 0)
		return TEE_ERROR_NOT_SUPPORTED;

	return cache_operation(s, op, va, len);
}
