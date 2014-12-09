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

#include <types_ext.h>
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>
#include <mm/core_mmu.h>
#include <tee/entry.h>
#include "plat_tee_func.h"

void plat_tee_entry(struct thread_smc_args *args)
{
	/*
	 * This function first catches all OPTEE specific SMC functions
	 * if none matches, the generic tee_entry is called.
	 */

	if (args->a0 == TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG) {
		args->a0 = TEESMC_RETURN_OK;
		args->a1 = default_nsec_shm_paddr;
		args->a2 = default_nsec_shm_size;
		/* Should this be TEESMC cache attributes instead? */
		args->a3 = core_mmu_is_shm_cached();
		return;
	}

	if (args->a0 == TEESMC32_OPTEE_FASTCALL_L2CC_MUTEX) {
		switch (args->a1) {
		case TEESMC_OPTEE_L2CC_MUTEX_GET_ADDR:
		case TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR:
		case TEESMC_OPTEE_L2CC_MUTEX_ENABLE:
		case TEESMC_OPTEE_L2CC_MUTEX_DISABLE:
			/* TODO call the appropriate internal functions */
			args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
			return;
		default:
			args->a0 = TEESMC_RETURN_EBADCMD;
			return;
		}
	}

	tee_entry(args);
}

/* Override weak function in tee/entry.c */
void tee_entry_get_api_call_count(struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count() + 2;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_api_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OPTEE_UID_R0;
	args->a1 = TEESMC_OPTEE_UID_R1;
	args->a2 = TEESMC_OPTEE_UID_R2;
	args->a3 = TEESMC_OPTEE_UID32_R3;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_api_revision(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OPTEE_REVISION_MAJOR;
	args->a1 = TEESMC_OPTEE_REVISION_MINOR;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_os_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OS_OPTEE_UUID_R0;
	args->a1 = TEESMC_OS_OPTEE_UUID_R1;
	args->a2 = TEESMC_OS_OPTEE_UUID_R2;
	args->a3 = TEESMC_OS_OPTEE_UUID_R3;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_os_revision(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OS_OPTEE_REVISION_MAJOR;
	args->a1 = TEESMC_OS_OPTEE_REVISION_MINOR;
}
