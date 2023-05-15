// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <initcall.h>
#include <trace.h>
#include <kernel/linker.h>

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_preinitcalls(void)
{
	const struct initcall *call = NULL;
	TEE_Result ret = TEE_SUCCESS;

	for (call = preinitcall_begin; call < preinitcall_end; call++) {
		DMSG("level %d %s()", call->level, call->func_name);
		ret = call->func();
		if (ret != TEE_SUCCESS) {
			EMSG("Preinitcall __text_start + 0x%08" PRIxVA
			     " failed", (vaddr_t)call - VCORE_START_VA);
		}
	}
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_initcalls(void)
{
	const struct initcall *call = NULL;
	TEE_Result ret = TEE_SUCCESS;

	for (call = initcall_begin; call < initcall_end; call++) {
		DMSG("level %d %s()", call->level, call->func_name);
		ret = call->func();
		if (ret != TEE_SUCCESS) {
			EMSG("Initcall __text_start + 0x%08" PRIxVA
			     " failed", (vaddr_t)call - VCORE_START_VA);
		}
	}
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_finalcalls(void)
{
	const struct initcall *call = NULL;
	TEE_Result ret = TEE_SUCCESS;

	for (call = finalcall_begin; call < finalcall_end; call++) {
		DMSG("level %d %s()", call->level, call->func_name);
		ret = call->func();
		if (ret != TEE_SUCCESS) {
			EMSG("Finalcall __text_start + 0x%08" PRIxVA
			     " failed", (vaddr_t)call - VCORE_START_VA);
		}
	}
}
