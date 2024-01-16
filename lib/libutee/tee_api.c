// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api.h>
#include <tee_internal_api_extensions.h>
#include <types_ext.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include "tee_api_private.h"

/*
 * return a known non-NULL invalid pointer when the
 * requested size is zero
 */
#define TEE_NULL_SIZED_VA		((void *)1)
#define TEE_NULL_SIZED_NO_SHARE_VA	((void *)2)

/*
 * Workaround build error in Teaclave TrustZone SDK
 *
 * These are supposed to be provided by ta/arch/arm/user_ta_header.c, but
 * Teaclave TrustZone SDK seems to roll their own in Rust.
 */
uint8_t __ta_no_share_heap[0] __weak;
const size_t __ta_no_share_heap_size __weak;
struct malloc_ctx *__ta_no_share_malloc_ctx __weak;

static const void *tee_api_instance_data;

/* System API - Internal Client API */

static void copy_param(struct utee_params *up, uint32_t param_types,
		       const TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n = 0;
	uint64_t a = 0;
	uint64_t b = 0;

	up->types = param_types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(up->types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			a = params[n].value.a;
			b = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			a = (vaddr_t)params[n].memref.buffer;
			b = params[n].memref.size;
			break;
		default:
			a = 0;
			b = 0;
		}
		up->vals[n * 2] = a;
		up->vals[n * 2 + 1] = b;
	}
}

static void copy_gp11_param(struct utee_params *up, uint32_t param_types,
			    const __GP11_TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n = 0;
	uint64_t a = 0;
	uint64_t b = 0;

	up->types = param_types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(up->types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			a = params[n].value.a;
			b = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			a = (vaddr_t)params[n].memref.buffer;
			b = params[n].memref.size;
			break;
		default:
			a = 0;
			b = 0;
		}
		up->vals[n * 2] = a;
		up->vals[n * 2 + 1] = b;
	}
}

static TEE_Result map_tmp_param(struct utee_params *up, void **tmp_buf,
				size_t *tmp_len, void *tmp_va[TEE_NUM_PARAMS])
{
	size_t n = 0;
	uint8_t *tb = NULL;
	size_t tbl = 0;
	size_t tmp_align = sizeof(vaddr_t) * 2;
	bool is_tmp_mem[TEE_NUM_PARAMS] = { false };
	void *b = NULL;
	size_t s = 0;
	const uint32_t flags = TEE_MEMORY_ACCESS_READ;

	/*
	 * If a memory parameter points to TA private memory we need to
	 * allocate a temporary buffer to avoid exposing the memory
	 * directly to the called TA.
	 */

	*tmp_buf = NULL;
	*tmp_len = 0;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		tmp_va[n] = NULL;
		switch (TEE_PARAM_TYPE_GET(up->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			b = (void *)(vaddr_t)up->vals[n * 2];
			s = up->vals[n * 2 + 1];
			/*
			 * We're only allocating temporary memory if the
			 * buffer is completely within TA memory. If it's
			 * NULL, empty, partially outside or completely
			 * outside TA memory there's nothing more we need
			 * to do here. If there's security/permissions
			 * problem we'll get an error in the
			 * invoke_command/open_session below.
			 */
			if (b && s &&
			    !TEE_CheckMemoryAccessRights(flags, b, s)) {
				is_tmp_mem[n] = true;
				tbl += ROUNDUP(s, tmp_align);
			}
			break;
		default:
			break;
		}
	}

	if (tbl) {
		tb = tee_map_zi(tbl, TEE_MEMORY_ACCESS_ANY_OWNER);
		if (!tb)
			return TEE_ERROR_OUT_OF_MEMORY;
		*tmp_buf = tb;
		*tmp_len = tbl;
	}

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(up->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			if (!is_tmp_mem[n])
				break;
			s = up->vals[n * 2 + 1];
			b = (void *)(vaddr_t)up->vals[n * 2];
			tmp_va[n] = tb;
			tb += ROUNDUP(s, tmp_align);
			up->vals[n * 2] = (vaddr_t)tmp_va[n];
			if (TEE_PARAM_TYPE_GET(up->types, n) !=
			    TEE_PARAM_TYPE_MEMREF_OUTPUT)
				memcpy(tmp_va[n], b, s);
			break;
		default:
			break;
		}
	}

	return TEE_SUCCESS;

}

static void update_out_param(TEE_Param params[TEE_NUM_PARAMS],
			     void *tmp_va[TEE_NUM_PARAMS],
			     const struct utee_params *up)
{
	size_t n;
	uint32_t types = up->types;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		uintptr_t b = up->vals[n * 2 + 1];

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value.a = a;
			params[n].value.b = b;
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (tmp_va[n])
				memcpy(params[n].memref.buffer, tmp_va[n],
				       MIN(b, params[n].memref.size));
			params[n].memref.size = b;
			break;
		default:
			break;
		}
	}
}

static void update_out_gp11_param(__GP11_TEE_Param params[TEE_NUM_PARAMS],
				  void *tmp_va[TEE_NUM_PARAMS],
				  const struct utee_params *up)
{
	size_t n = 0;
	uint32_t types = up->types;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		uintptr_t b = up->vals[n * 2 + 1];

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value.a = a;
			params[n].value.b = b;
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (tmp_va[n])
				memcpy(params[n].memref.buffer, tmp_va[n],
				       MIN(b, params[n].memref.size));
			params[n].memref.size = b;
			break;
		default:
			break;
		}
	}
}

static bool bufs_intersect(void *buf1, size_t sz1, void *buf2, size_t sz2)
{
	vaddr_t b1 = (vaddr_t)buf1;
	vaddr_t b2 = (vaddr_t)buf2;
	vaddr_t e1 = b1 + sz1 - 1;
	vaddr_t e2 = b2 + sz2 - 1;

	if (!sz1 || !sz2)
		return false;

	if (e1 < b2 || e2 < b1)
		return false;

	return true;
}

static TEE_Result check_mem_access_rights_params(uint32_t flags, void *buf,
						 size_t len)
{
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t f = TEE_MEMORY_ACCESS_ANY_OWNER;

		switch (TEE_PARAM_TYPE_GET(ta_param_types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			f |= TEE_MEMORY_ACCESS_WRITE;
			fallthrough;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			f |= TEE_MEMORY_ACCESS_READ;
			if (bufs_intersect(buf, len,
					   ta_params[n].memref.buffer,
					   ta_params[n].memref.size)) {
				if ((flags & f) != flags)
					return TEE_ERROR_ACCESS_DENIED;
			}
			break;
		default:
			break;
		}
	}

	return TEE_SUCCESS;
}

static bool buf_overlaps_no_share_heap(void *buf, size_t size)
{
	struct malloc_ctx *ctx = __ta_no_share_malloc_ctx;

	return ctx && raw_malloc_buffer_overlaps_heap(ctx, buf, size);
}

static void check_invoke_param(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t f = TEE_MEMORY_ACCESS_ANY_OWNER;
		void *buf = params[n].memref.buffer;
		size_t size = params[n].memref.size;

		switch (TEE_PARAM_TYPE_GET(pt, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			f |= TEE_MEMORY_ACCESS_WRITE;
			fallthrough;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			f |= TEE_MEMORY_ACCESS_READ;
			if (check_mem_access_rights_params(f, buf, size))
				TEE_Panic(0);
			if (buf_overlaps_no_share_heap(buf, size))
				TEE_Panic(0);
			break;
		default:
			break;
		}
	}
}

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
				uint32_t cancellationRequestTimeout,
				uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				TEE_TASessionHandle *session,
				uint32_t *returnOrigin)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params up = { };
	uint32_t s = 0;
	void *tmp_buf = NULL;
	size_t tmp_len = 0;
	void *tmp_va[TEE_NUM_PARAMS] = { NULL };

	if (paramTypes) {
		__utee_check_inout_annotation(params,
					      sizeof(TEE_Param) *
					      TEE_NUM_PARAMS);
		check_invoke_param(paramTypes, params);
	}
	__utee_check_out_annotation(session, sizeof(*session));

	copy_param(&up, paramTypes, params);
	res = map_tmp_param(&up, &tmp_buf, &tmp_len, tmp_va);
	if (res)
		goto out;
	res = _utee_open_ta_session(destination, cancellationRequestTimeout,
				    &up, &s, returnOrigin);
	update_out_param(params, tmp_va, &up);
	if (tmp_buf) {
		TEE_Result res2 = tee_unmap(tmp_buf, tmp_len);

		if (res2)
			TEE_Panic(res2);
	}

out:
	/*
	 * Specification says that *session must hold TEE_HANDLE_NULL is
	 * TEE_SUCCESS isn't returned. Set it here explicitly in case
	 * the syscall fails before out parameters has been updated.
	 */
	if (res != TEE_SUCCESS)
		s = TEE_HANDLE_NULL;

	*session = (TEE_TASessionHandle)(uintptr_t)s;
	return res;
}

TEE_Result __GP11_TEE_OpenTASession(const TEE_UUID *destination,
				    uint32_t cancellationRequestTimeout,
				    uint32_t paramTypes,
				    __GP11_TEE_Param params[TEE_NUM_PARAMS],
				    TEE_TASessionHandle *session,
				    uint32_t *returnOrigin)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params up = { };
	uint32_t s = 0;
	void *tmp_buf = NULL;
	size_t tmp_len = 0;
	void *tmp_va[TEE_NUM_PARAMS] = { NULL };

	if (paramTypes)
		__utee_check_inout_annotation(params,
					      sizeof(__GP11_TEE_Param) *
					      TEE_NUM_PARAMS);
	__utee_check_out_annotation(session, sizeof(*session));

	copy_gp11_param(&up, paramTypes, params);
	res = map_tmp_param(&up, &tmp_buf, &tmp_len, tmp_va);
	if (res)
		goto out;
	res = _utee_open_ta_session(destination, cancellationRequestTimeout,
				    &up, &s, returnOrigin);
	update_out_gp11_param(params, tmp_va, &up);
	if (tmp_buf) {
		TEE_Result res2 = tee_unmap(tmp_buf, tmp_len);

		if (res2)
			TEE_Panic(res2);
	}

out:
	/*
	 * Specification says that *session must hold TEE_HANDLE_NULL if
	 * TEE_SUCCESS isn't returned. Set it here explicitly in case
	 * the syscall fails before out parameters has been updated.
	 */
	if (res != TEE_SUCCESS)
		s = TEE_HANDLE_NULL;

	*session = (TEE_TASessionHandle)(uintptr_t)s;
	return res;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
	if (session != TEE_HANDLE_NULL) {
		TEE_Result res = _utee_close_ta_session((uintptr_t)session);

		if (res != TEE_SUCCESS)
			TEE_Panic(res);
	}
}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
				uint32_t cancellationRequestTimeout,
				uint32_t commandID, uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				uint32_t *returnOrigin)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_origin = TEE_ORIGIN_TEE;
	struct utee_params up = { };
	void *tmp_buf = NULL;
	size_t tmp_len = 0;
	void *tmp_va[TEE_NUM_PARAMS] = { NULL };

	if (paramTypes) {
		__utee_check_inout_annotation(params,
					      sizeof(TEE_Param) *
					      TEE_NUM_PARAMS);
		check_invoke_param(paramTypes, params);
	}
	if (returnOrigin)
		__utee_check_out_annotation(returnOrigin,
					    sizeof(*returnOrigin));

	copy_param(&up, paramTypes, params);
	res = map_tmp_param(&up, &tmp_buf, &tmp_len, tmp_va);
	if (res)
		goto out;
	res = _utee_invoke_ta_command((uintptr_t)session,
				      cancellationRequestTimeout,
				      commandID, &up, &ret_origin);
	update_out_param(params, tmp_va, &up);
	if (tmp_buf) {
		TEE_Result res2 = tee_unmap(tmp_buf, tmp_len);

		if (res2)
			TEE_Panic(res2);
	}

out:
	if (returnOrigin != NULL)
		*returnOrigin = ret_origin;

	if (ret_origin == TEE_ORIGIN_TRUSTED_APP)
		return res;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_TARGET_DEAD)
		TEE_Panic(res);

	return res;
}

TEE_Result __GP11_TEE_InvokeTACommand(TEE_TASessionHandle session,
				      uint32_t cancellationRequestTimeout,
				      uint32_t commandID, uint32_t paramTypes,
				      __GP11_TEE_Param params[TEE_NUM_PARAMS],
				      uint32_t *returnOrigin)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_origin = TEE_ORIGIN_TEE;
	struct utee_params up = { };
	void *tmp_buf = NULL;
	size_t tmp_len = 0;
	void *tmp_va[TEE_NUM_PARAMS] = { NULL };

	if (paramTypes)
		__utee_check_inout_annotation(params,
					      sizeof(__GP11_TEE_Param) *
					      TEE_NUM_PARAMS);
	if (returnOrigin)
		__utee_check_out_annotation(returnOrigin,
					    sizeof(*returnOrigin));

	copy_gp11_param(&up, paramTypes, params);
	res = map_tmp_param(&up, &tmp_buf, &tmp_len, tmp_va);
	if (res)
		goto out;
	res = _utee_invoke_ta_command((uintptr_t)session,
				      cancellationRequestTimeout,
				      commandID, &up, &ret_origin);
	update_out_gp11_param(params, tmp_va, &up);
	if (tmp_buf) {
		TEE_Result res2 = tee_unmap(tmp_buf, tmp_len);

		if (res2)
			TEE_Panic(res2);
	}

out:
	if (returnOrigin)
		*returnOrigin = ret_origin;

	if (ret_origin == TEE_ORIGIN_TRUSTED_APP)
		return res;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_TARGET_DEAD)
		TEE_Panic(res);

	return res;
}

/* System API - Cancellations */

bool TEE_GetCancellationFlag(void)
{
	uint32_t c;
	TEE_Result res = _utee_get_cancellation_flag(&c);

	if (res != TEE_SUCCESS)
		c = 0;
	return !!c;
}

bool TEE_UnmaskCancellation(void)
{
	uint32_t old_mask;
	TEE_Result res = _utee_unmask_cancellation(&old_mask);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return !!old_mask;
}

bool TEE_MaskCancellation(void)
{
	uint32_t old_mask;
	TEE_Result res = _utee_mask_cancellation(&old_mask);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return !!old_mask;
}

/* System API - Memory Management */

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
				       size_t size)
{
	uint32_t flags = accessFlags;

	if (!size)
		return TEE_SUCCESS;

	/*
	 * Check access rights against memory mapping. If this check is
	 * OK the size can't cause an overflow when added with buffer.
	 */
	if (_utee_check_access_rights(accessFlags, buffer, size))
		return TEE_ERROR_ACCESS_DENIED;

	/*
	 * Check access rights against input parameters.
	 *
	 * Clear eventual extension flags like TEE_MEMORY_ACCESS_NONSECURE
	 * and TEE_MEMORY_ACCESS_SECURE.
	 */
	flags &= TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE |
		 TEE_MEMORY_ACCESS_ANY_OWNER;
	if (check_mem_access_rights_params(flags, buffer, size))
		return TEE_ERROR_ACCESS_DENIED;

	if (malloc_buffer_overlaps_heap(buffer, size) &&
	    !malloc_buffer_is_within_alloced(buffer, size))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result __GP11_TEE_CheckMemoryAccessRights(uint32_t accessFlags,
					      void *buffer, uint32_t size)
{
	return TEE_CheckMemoryAccessRights(accessFlags, buffer, size);
}

void TEE_SetInstanceData(const void *instanceData)
{
	tee_api_instance_data = instanceData;
}

const void *TEE_GetInstanceData(void)
{
	return tee_api_instance_data;
}

void *TEE_MemMove(void *dest, const void *src, size_t size)
{
	return memmove(dest, src, size);
}

void *__GP11_TEE_MemMove(void *dest, const void *src, uint32_t size)
{
	return TEE_MemMove(dest, src, size);
}

int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, size_t size)
{
	return consttime_memcmp(buffer1, buffer2, size);
}

int32_t __GP11_TEE_MemCompare(const void *buffer1, const void *buffer2,
			      uint32_t size)
{
	return TEE_MemCompare(buffer1, buffer2, size);
}

void TEE_MemFill(void *buff, uint32_t x, size_t size)
{
	memset(buff, x, size);
}

void __GP11_TEE_MemFill(void *buff, uint32_t x, uint32_t size)
{
	TEE_MemFill(buff, x, size);
}

/* Date & Time API */

void TEE_GetSystemTime(TEE_Time *time)
{
	TEE_Result res = _utee_get_time(UTEE_TIME_CAT_SYSTEM, time);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_Wait(uint32_t timeout)
{
	TEE_Result res = _utee_wait(timeout);

	if (res != TEE_SUCCESS && res != TEE_ERROR_CANCEL)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
	TEE_Result res;

	res = _utee_get_time(UTEE_TIME_CAT_TA_PERSISTENT, time);

	if (res != TEE_SUCCESS && res != TEE_ERROR_OVERFLOW) {
		time->seconds = 0;
		time->millis = 0;
	}

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_TIME_NOT_SET &&
	    res != TEE_ERROR_TIME_NEEDS_RESET &&
	    res != TEE_ERROR_OVERFLOW &&
	    res != TEE_ERROR_OUT_OF_MEMORY)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_SetTAPersistentTime(const TEE_Time *time)
{
	TEE_Result res;

	res = _utee_set_ta_time(time);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_STORAGE_NO_SPACE)
		TEE_Panic(res);

	return res;
}

void TEE_GetREETime(TEE_Time *time)
{
	TEE_Result res = _utee_get_time(UTEE_TIME_CAT_REE, time);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

void *TEE_Malloc(size_t len, uint32_t hint)
{
	switch (hint) {
	case TEE_MALLOC_FILL_ZERO:
		if (!len)
			return TEE_NULL_SIZED_VA;
		return calloc(1, len);

	case TEE_MALLOC_NO_FILL:
		TEE_Panic(0);
		break;

	case TEE_MALLOC_NO_SHARE:
		if (!len)
			return TEE_NULL_SIZED_NO_SHARE_VA;
		if (!__ta_no_share_malloc_ctx)
			return NULL;
		return raw_calloc(0, 0, 1, len, __ta_no_share_malloc_ctx);

	case TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE:
		if (!len)
			return TEE_NULL_SIZED_NO_SHARE_VA;
		if (!__ta_no_share_malloc_ctx)
			return NULL;
		return raw_malloc(0, 0, len, __ta_no_share_malloc_ctx);

	case TEE_USER_MEM_HINT_NO_FILL_ZERO:
		if (!len)
			return TEE_NULL_SIZED_VA;
		return malloc(len);

	default:
		break;
	}

	EMSG("Invalid hint %#" PRIx32, hint);

	return NULL;
}

void *__GP11_TEE_Malloc(uint32_t size, uint32_t hint)
{
	return TEE_Malloc(size, hint);
}

static bool addr_is_in_no_share_heap(void *p)
{
	return buf_overlaps_no_share_heap(p, 1);
}

void *TEE_Realloc(void *buffer, size_t newSize)
{
	if (!newSize) {
		void *ret = NULL;

		if (addr_is_in_no_share_heap(buffer))
			ret = TEE_NULL_SIZED_NO_SHARE_VA;
		else
			ret = TEE_NULL_SIZED_VA;

		TEE_Free(buffer);

		return ret;
	}

	if (buffer == TEE_NULL_SIZED_VA)
		return calloc(1, newSize);
	if (buffer == TEE_NULL_SIZED_NO_SHARE_VA) {
		if (!__ta_no_share_malloc_ctx)
			return NULL;
		return raw_calloc(0, 0, 1, newSize, __ta_no_share_malloc_ctx);
	}

	if (addr_is_in_no_share_heap(buffer))
		return raw_realloc(buffer, 0, 0, newSize,
				   __ta_no_share_malloc_ctx);
	else
		return realloc(buffer, newSize);
}

void *__GP11_TEE_Realloc(void *buffer, uint32_t newSize)
{
	return TEE_Realloc(buffer, newSize);
}

void TEE_Free(void *buffer)
{
	if (buffer != TEE_NULL_SIZED_VA &&
	    buffer != TEE_NULL_SIZED_NO_SHARE_VA) {
		if (addr_is_in_no_share_heap(buffer))
			raw_free(buffer, __ta_no_share_malloc_ctx, false);
		else
			free(buffer);
	}
}

/* Cache maintenance support (TA requires the CACHE_MAINTENANCE property) */
TEE_Result TEE_CacheClean(char *buf, size_t len)
{
	return _utee_cache_operation(buf, len, TEE_CACHECLEAN);
}
TEE_Result TEE_CacheFlush(char *buf, size_t len)
{
	return _utee_cache_operation(buf, len, TEE_CACHEFLUSH);
}

TEE_Result TEE_CacheInvalidate(char *buf, size_t len)
{
	return _utee_cache_operation(buf, len, TEE_CACHEINVALIDATE);
}
