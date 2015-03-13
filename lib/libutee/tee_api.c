/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <stdlib.h>
#include <string.h>

#include <tee_api.h>
#include <utee_syscalls.h>
#include <user_ta_header.h>
#include "tee_user_mem.h"

static void *tee_api_instance_data;

/* System API - Misc */

void TEE_Panic(TEE_Result panicCode)
{
	utee_panic(panicCode);
}

/* System API - Internal Client API */

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
			     uint32_t cancellationRequestTimeout,
			     uint32_t paramTypes, TEE_Param params[4],
			     TEE_TASessionHandle *session,
			     uint32_t *returnOrigin)
{
	TEE_Result res;

	res = utee_open_ta_session(destination, cancellationRequestTimeout,
				   paramTypes, params, session, returnOrigin);
	/*
	 * Specification says that *session must hold TEE_HANDLE_NULL is
	 * TEE_SUCCESS isn't returned. Set it here explicitly in case
	 * the syscall fails before out parameters has been updated.
	 */
	if (res != TEE_SUCCESS)
		*session = TEE_HANDLE_NULL;

	return res;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
	if (session != TEE_HANDLE_NULL) {
		TEE_Result res = utee_close_ta_session(session);
		if (res != TEE_SUCCESS)
			TEE_Panic(res);
	}
}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
			       uint32_t cancellationRequestTimeout,
			       uint32_t commandID, uint32_t paramTypes,
			       TEE_Param params[4], uint32_t *returnOrigin)
{
	return utee_invoke_ta_command(session, cancellationRequestTimeout,
				      commandID, paramTypes, params,
				      returnOrigin);
}

/* System API - Cancellations */

bool TEE_GetCancellationFlag(void)
{
	bool c;
	TEE_Result res = utee_get_cancellation_flag(&c);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return c;
}

bool TEE_UnmaskCancellation(void)
{
	bool old_mask;
	TEE_Result res = utee_unmask_cancellation(&old_mask);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return old_mask;
}

bool TEE_MaskCancellation(void)
{
	bool old_mask;
	TEE_Result res = utee_mask_cancellation(&old_mask);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	return old_mask;
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

void TEE_SetInstanceData(void *instanceData)
{
	tee_api_instance_data = instanceData;
}

void *TEE_GetInstanceData(void)
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
		TEE_Panic(0);
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
	return utee_get_time(UTEE_TIME_CAT_TA_PERSISTENT, time);
}

TEE_Result TEE_SetTAPersistentTime(const TEE_Time *time)
{
	return utee_set_ta_time(time);
}

void TEE_GetREETime(TEE_Time *time)
{
	TEE_Result res = utee_get_time(UTEE_TIME_CAT_REE, time);

	if (res != TEE_SUCCESS)
		TEE_Panic(0);
}

void *TEE_Malloc(uint32_t len, uint32_t hint)
{
	return tee_user_mem_alloc(len, hint);
}

void *TEE_Realloc(void *buffer, uint32_t newSize)
{
	/*
	 * GP TEE Internal API specifies newSize as 'uint32_t'.
	 * use unsigned 'size_t' type. it is at least 32bit!
	 */
	return tee_user_mem_realloc(buffer, (size_t) newSize);
}

void TEE_Free(void *buffer)
{
	tee_user_mem_free(buffer);
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
