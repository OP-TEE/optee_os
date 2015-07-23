/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
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

#include <tee/entry_fast.h>
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>

#include <assert.h>

static void tee_entry_get_shm_config(struct thread_smc_args *args)
{
	args->a0 = TEESMC_RETURN_OK;
	args->a1 = default_nsec_shm_paddr;
	args->a2 = default_nsec_shm_size;
	/* Should this be TEESMC cache attributes instead? */
	args->a3 = core_mmu_is_shm_cached();
}

static void tee_entry_fastcall_l2cc_mutex(struct thread_smc_args *args)
{
	TEE_Result ret;

#ifdef ARM32
	switch (args->a1) {
	case TEESMC_OPTEE_L2CC_MUTEX_GET_ADDR:
		ret = tee_get_l2cc_mutex(&args->a2);
		break;
	case TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR:
		ret = tee_set_l2cc_mutex(&args->a2);
		break;
	case TEESMC_OPTEE_L2CC_MUTEX_ENABLE:
		ret = tee_enable_l2cc_mutex();
		break;
	case TEESMC_OPTEE_L2CC_MUTEX_DISABLE:
		ret = tee_disable_l2cc_mutex();
		break;
	default:
		args->a0 = TEESMC_RETURN_EBADCMD;
		return;
	}
#else
	ret = TEE_ERROR_NOT_SUPPORTED;
#endif
	if (ret == TEE_ERROR_NOT_SUPPORTED)
		args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
	else if (ret)
		args->a0 = TEESMC_RETURN_EBADADDR;
	else
		args->a0 = TEESMC_RETURN_OK;
}

void tee_entry_fast(struct thread_smc_args *args)
{
	switch (args->a0) {

	/* Generic functions */
	case TEESMC32_CALLS_COUNT:
		tee_entry_get_api_call_count(args);
		break;
	case TEESMC32_CALLS_UID:
		tee_entry_get_api_uuid(args);
		break;
	case TEESMC32_CALLS_REVISION:
		tee_entry_get_api_revision(args);
		break;
	case TEESMC32_CALL_GET_OS_UUID:
		tee_entry_get_os_uuid(args);
		break;
	case TEESMC32_CALL_GET_OS_REVISION:
		tee_entry_get_os_revision(args);
		break;

	/* OP-TEE specific SMC functions */
	case TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG:
		tee_entry_get_shm_config(args);
		break;
	case TEESMC32_OPTEE_FASTCALL_L2CC_MUTEX:
		tee_entry_fastcall_l2cc_mutex(args);
		break;
	default:
		args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}

size_t tee_entry_generic_get_api_call_count(void)
{
	/*
	 * All the different calls handled in this file. If the specific
	 * target has additional calls it will call this function and
	 * add the number of calls the target has added.
	 */
	return 9;
}

void __weak tee_entry_get_api_call_count(struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count();
}

void __weak tee_entry_get_api_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OPTEE_UID_R0;
	args->a1 = TEESMC_OPTEE_UID_R1;
	args->a2 = TEESMC_OPTEE_UID_R2;
	args->a3 = TEESMC_OPTEE_UID32_R3;
}

void __weak tee_entry_get_api_revision(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OPTEE_REVISION_MAJOR;
	args->a1 = TEESMC_OPTEE_REVISION_MINOR;
}

void __weak tee_entry_get_os_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OS_OPTEE_UUID_R0;
	args->a1 = TEESMC_OS_OPTEE_UUID_R1;
	args->a2 = TEESMC_OS_OPTEE_UUID_R2;
	args->a3 = TEESMC_OS_OPTEE_UUID_R3;
}

void __weak tee_entry_get_os_revision(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OS_OPTEE_REVISION_MAJOR;
	args->a1 = TEESMC_OS_OPTEE_REVISION_MINOR;
}
