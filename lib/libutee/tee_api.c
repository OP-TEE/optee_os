// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <string.h>

#include <tee_api.h>
#include <tee_internal_api_extensions.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include "tee_api_private.h"

static const void *tee_api_instance_data;

/* System API - Internal Client API */

void __utee_from_param(struct utee_params *up, uint32_t param_types,
			const TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n;

	up->types = param_types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			up->vals[n * 2] = params[n].value.a;
			up->vals[n * 2 + 1] = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			up->vals[n * 2] = (uintptr_t)params[n].memref.buffer;
			up->vals[n * 2 + 1] = params[n].memref.size;
			break;
		default:
			up->vals[n * 2] = 0;
			up->vals[n * 2 + 1] = 0;
			break;
		}
	}
}

void __utee_to_param(TEE_Param params[TEE_NUM_PARAMS],
			uint32_t *param_types, const struct utee_params *up)
{
	size_t n;
	uint32_t types = up->types;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		uintptr_t b = up->vals[n * 2 + 1];

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value.a = a;
			params[n].value.b = b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[n].memref.buffer = (void *)a;
			params[n].memref.size = b;
			break;
		default:
			break;
		}
	}

	if (param_types)
		*param_types = types;
}

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
				uint32_t cancellationRequestTimeout,
				uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				TEE_TASessionHandle *session,
				uint32_t *returnOrigin)
{
	TEE_Result res;
	struct utee_params up;
	uint32_t s;

	__utee_from_param(&up, paramTypes, params);
	res = utee_open_ta_session(destination, cancellationRequestTimeout,
				   &up, &s, returnOrigin);
	__utee_to_param(params, NULL, &up);
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

void TEE_CloseTASession(TEE_TASessionHandle session)
{
	if (session != TEE_HANDLE_NULL) {
		TEE_Result res = utee_close_ta_session((uintptr_t)session);

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
	TEE_Result res;
	uint32_t ret_origin;
	struct utee_params up;

	__utee_from_param(&up, paramTypes, params);
	res = utee_invoke_ta_command((uintptr_t)session,
				      cancellationRequestTimeout,
				      commandID, &up, &ret_origin);
	__utee_to_param(params, NULL, &up);

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

/* System API - Cancellations */

bool TEE_GetCancellationFlag(void)
{
	uint32_t c;
	TEE_Result res = utee_get_cancellation_flag(&c);

	if (res != TEE_SUCCESS)
		c = 0;
	return !!c;
}

bool TEE_UnmaskCancellation(void)
{
	uint32_t old_mask;
	TEE_Result res = utee_unmask_cancellation(&old_mask);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return !!old_mask;
}

bool TEE_MaskCancellation(void)
{
	uint32_t old_mask;
	TEE_Result res = utee_mask_cancellation(&old_mask);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return !!old_mask;
}

/* System API - Memory Management */

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
				       uint32_t size)
{
	TEE_Result res;

	if (size == 0)
		return TEE_SUCCESS;

	/* Check access rights against memory mapping */
	res = utee_check_access_rights(accessFlags, buffer, size);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	* Check access rights against input parameters
	* Previous legacy code was removed and will need to be restored
	*/

	res = TEE_SUCCESS;
out:
	return res;
}

void TEE_SetInstanceData(const void *instanceData)
{
	tee_api_instance_data = instanceData;
}

const void *TEE_GetInstanceData(void)
{
	return tee_api_instance_data;
}

void *TEE_MemMove(void *dest, const void *src, uint32_t size)
{
	return memmove(dest, src, size);
}

int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, uint32_t size)
{
	return memcmp(buffer1, buffer2, size);
}

void *TEE_MemFill(void *buff, uint32_t x, uint32_t size)
{
	return memset(buff, x, size);
}

/* Date & Time API */

void TEE_GetSystemTime(TEE_Time *time)
{
	TEE_Result res = utee_get_time(UTEE_TIME_CAT_SYSTEM, time);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_Wait(uint32_t timeout)
{
	TEE_Result res = utee_wait(timeout);

	if (res != TEE_SUCCESS && res != TEE_ERROR_CANCEL)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
	TEE_Result res;

	res = utee_get_time(UTEE_TIME_CAT_TA_PERSISTENT, time);

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

	res = utee_set_ta_time(time);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_STORAGE_NO_SPACE)
		TEE_Panic(res);

	return res;
}

void TEE_GetREETime(TEE_Time *time)
{
	TEE_Result res = utee_get_time(UTEE_TIME_CAT_REE, time);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

void *TEE_Malloc(uint32_t len, uint32_t hint)
{
	if (hint == TEE_MALLOC_FILL_ZERO)
		return calloc(1, len);
	else if (hint == TEE_USER_MEM_HINT_NO_FILL_ZERO)
		return malloc(len);

	EMSG("Invalid hint %#" PRIx32, hint);

	return NULL;
}

void *TEE_Realloc(void *buffer, uint32_t newSize)
{
	return realloc(buffer, newSize);
}

void TEE_Free(void *buffer)
{
	free(buffer);
}

/* Cache maintenance support (TA requires the CACHE_MAINTENANCE property) */
TEE_Result TEE_CacheClean(char *buf, size_t len)
{
	return utee_cache_operation(buf, len, TEE_CACHECLEAN);
}
TEE_Result TEE_CacheFlush(char *buf, size_t len)
{
	return utee_cache_operation(buf, len, TEE_CACHEFLUSH);
}

TEE_Result TEE_CacheInvalidate(char *buf, size_t len)
{
	return utee_cache_operation(buf, len, TEE_CACHEINVALIDATE);
}
