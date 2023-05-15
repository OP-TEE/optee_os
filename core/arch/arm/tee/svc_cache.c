// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
 */

#include <kernel/tee_ta_manager.h>
#include <mm/vm.h>
#include <tee/cache.h>
#include <tee/svc_cache.h>

TEE_Result syscall_cache_operation(void *va, size_t len, unsigned long op)
{
	struct ts_session *s = ts_get_current_session();
	struct user_ta_ctx *utc = NULL;
	TEE_Result res = TEE_SUCCESS;

	if ((to_ta_ctx(s->ctx)->flags & TA_FLAG_CACHE_MAINTENANCE) == 0)
		return TEE_ERROR_NOT_SUPPORTED;

	utc = to_user_ta_ctx(s->ctx);

	/*
	 * TAs are allowed to operate cache maintenance on TA memref parameters
	 * only, not on the TA private memory.
	 */
	if (vm_buf_intersects_um_private(&utc->uctx, va, len))
		return TEE_ERROR_ACCESS_DENIED;

	res = vm_check_access_rights(&utc->uctx,
				     TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)va, len);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_DENIED;

	return cache_operation(op, va, len);
}
