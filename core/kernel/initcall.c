// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <initcall.h>
#include <trace.h>
#include <kernel/linker.h>

static void call_inits(const char *name __maybe_unused,
		       const struct initcall *begin, const struct initcall *end)
{
	const struct initcall *call = NULL;
	TEE_Result ret = TEE_SUCCESS;

	for (call = begin; call < end; call++) {
		DMSG("level %d %s()", call->level, call->func_name);
		ret = call->func();
		if (ret != TEE_SUCCESS) {
			EMSG("%scall __text_start + 0x%08"PRIxVA" failed",
			     name, (vaddr_t)call - VCORE_START_VA);
		}
	}
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_initcalls(void)
{
	call_inits("Init", initcall_begin, initcall_end);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_finalcalls(void)
{
	call_inits("Final", finalcall_begin, finalcall_end);
}

#ifdef CFG_CORE_DEFERRED_INIT
/*
 * No need to exclude this from the unpaged area as it's expected to be
 * called from a PTA.
 */
void call_deferredcalls(void)
{
	call_inits("Deferred", deferredcall_begin, deferredcall_end);
}
#endif /*CFG_CORE_DEFERRED_INIT*/
