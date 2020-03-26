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
#include "pta_system.h"
#include "tee_api_private.h"

static const void *tee_api_instance_data;

TEE_TASessionHandle __tee_api_system_session;

/* System API - Internal Client API */

static TEE_Result copy_param(struct utee_params *up, uint32_t param_types,
			     const TEE_Param params[TEE_NUM_PARAMS],
			     void **tmp_buf, size_t *tmp_len,
			     void *tmp_va[TEE_NUM_PARAMS])
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
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			b = params[n].memref.buffer;
			s = params[n].memref.size;
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

	up->types = param_types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			up->vals[n * 2] = params[n].value.a;
			up->vals[n * 2 + 1] = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			s = params[n].memref.size;
			if (is_tmp_mem[n]) {
				b = tb;
				tmp_va[n] = tb;
				tb += ROUNDUP(s, tmp_align);
				if (TEE_PARAM_TYPE_GET(param_types, n) !=
				    TEE_PARAM_TYPE_MEMREF_OUTPUT)
					memcpy(b, params[n].memref.buffer, s);
			} else {
				b = params[n].memref.buffer;
			}
			up->vals[n * 2] = (vaddr_t)b;
			up->vals[n * 2 + 1] = s;
			break;
		default:
			up->vals[n * 2] = 0;
			up->vals[n * 2 + 1] = 0;
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

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
				uint32_t cancellationRequestTimeout,
				uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				TEE_TASessionHandle *session,
				uint32_t *returnOrigin)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params up;
	uint32_t s = 0;
	void *tmp_buf = NULL;
	size_t tmp_len = 0;
	void *tmp_va[TEE_NUM_PARAMS] = { NULL };

	if (paramTypes)
		__utee_check_inout_annotation(params,
					      sizeof(TEE_Param) *
					      TEE_NUM_PARAMS);
	__utee_check_out_annotation(session, sizeof(*session));

	res = copy_param(&up, paramTypes, params, &tmp_buf, &tmp_len, tmp_va);
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
	struct utee_params up;
	void *tmp_buf = NULL;
	size_t tmp_len = 0;
	void *tmp_va[TEE_NUM_PARAMS] = { NULL };

	if (paramTypes)
		__utee_check_inout_annotation(params,
					      sizeof(TEE_Param) *
					      TEE_NUM_PARAMS);
	if (returnOrigin)
		__utee_check_out_annotation(returnOrigin,
					    sizeof(*returnOrigin));

	res = copy_param(&up, paramTypes, params, &tmp_buf, &tmp_len, tmp_va);
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

#ifdef CFG_OCALL
TEE_Result TEE_InvokeCACommand(uint32_t cancellationRequestTimeout,
			       uint32_t commandID, uint32_t paramTypes,
			       TEE_Param params[TEE_NUM_PARAMS],
			       uint32_t *returnOrigin)
{
	const TEE_UUID uuid = PTA_SYSTEM_UUID;
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_origin = TEE_ORIGIN_TEE;
	struct utee_params pta_up = { };
	struct utee_params ocall_up = { };
	void *buffer = NULL;
	size_t size = 0;
	size_t n = 0;

	if (paramTypes)
		__utee_check_inout_annotation(params,
					      sizeof(TEE_Param) *
					      TEE_NUM_PARAMS);
	if (returnOrigin)
		__utee_check_out_annotation(returnOrigin,
					    sizeof(*returnOrigin));

	/* Open session with the System PTA, if necessary */
	if (__tee_api_system_session == TEE_HANDLE_NULL) {
		res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
					&__tee_api_system_session, &ret_origin);
		/* The System PTA is optional */
		if (res == TEE_ERROR_ITEM_NOT_FOUND &&
		    ret_origin == TEE_ORIGIN_TEE) {
			res = TEE_ERROR_NOT_SUPPORTED;
			ret_origin = TEE_ORIGIN_API;
		}
		if (res)
			goto exit;
	}

	/* Convert the OCALL's parameters into a utee_params structure */
	ocall_up.types = paramTypes;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(paramTypes, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			ocall_up.vals[n * 2] = params[n].value.a;
			ocall_up.vals[n * 2 + 1] = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			buffer = params[n].memref.buffer;
			size = params[n].memref.size;
			if ((buffer && !size) || (!buffer && size)) {
				res = TEE_ERROR_BAD_PARAMETERS;
				ret_origin = TEE_ORIGIN_API;
				goto exit;
			}
			ocall_up.vals[n * 2] = (vaddr_t)buffer;
			ocall_up.vals[n * 2 + 1] = size;
			break;
		default:
			break;
		}
	}

	/* Construct the parameters for the call to the PTA */
	pta_up.vals[0] = commandID;
	pta_up.vals[2] = (uintptr_t)&ocall_up;
	pta_up.vals[3] = sizeof(ocall_up);
	pta_up.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				       TEE_PARAM_TYPE_MEMREF_INOUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	/* Send the OCALL request */
	res = _utee_invoke_ta_command((uintptr_t)__tee_api_system_session,
				      cancellationRequestTimeout,
				      PTA_SYSTEM_OCALL,
				      &pta_up,
				      &ret_origin);
	if (res != TEE_SUCCESS)
		goto exit;

	/* Convert the utee_params structure into the OCALL's parameters */
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(paramTypes, n)) {
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value.a = ocall_up.vals[n * 2];
			params[n].value.b = ocall_up.vals[n * 2 + 1];
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			buffer = (void *)(uintptr_t)ocall_up.vals[n * 2];
			size = ocall_up.vals[n * 2 + 1];
			if (buffer != params[n].memref.buffer ||
			    size > params[n].memref.size) {
				res = TEE_ERROR_BAD_PARAMETERS;
				ret_origin = TEE_ORIGIN_API;
				goto exit;
			}
			params[n].memref.size = size;
			break;
		default:
			break;
		}
	}

	/* Extract the OCALL return value and error origin */
	res = (TEE_Result)pta_up.vals[0];
	ret_origin = (uint32_t)pta_up.vals[1];

exit:
	/* The PTA is a communications conduit to normal world */
	if (ret_origin == TEE_ORIGIN_TRUSTED_APP)
		ret_origin = TEE_ORIGIN_COMMS;

	if (returnOrigin)
		*returnOrigin = ret_origin;

	if (ret_origin == TEE_ORIGIN_TEE &&
	    (res != TEE_SUCCESS ||
	     res != TEE_ERROR_OUT_OF_MEMORY ||
	     res != TEE_ERROR_TARGET_DEAD))
		TEE_Panic(res);

	return res;
}
#else
TEE_Result TEE_InvokeCACommand(uint32_t cancellationRequestTimeout __unused,
			       uint32_t commandID __unused,
			       uint32_t paramTypes __unused,
			       TEE_Param params[TEE_NUM_PARAMS]  __unused,
			       uint32_t *returnOrigin __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*CFG_OCALL*/

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
				       uint32_t size)
{
	TEE_Result res;

	if (size == 0)
		return TEE_SUCCESS;

	/* Check access rights against memory mapping */
	res = _utee_check_access_rights(accessFlags, buffer, size);
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
	return consttime_memcmp(buffer1, buffer2, size);
}

void *TEE_MemFill(void *buff, uint32_t x, uint32_t size)
{
	return memset(buff, x, size);
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
