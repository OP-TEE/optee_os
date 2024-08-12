// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <initcall.h>
#include <trace.h>
#include <kernel/linker.h>

static void do_init_calls(const char *type __maybe_unused,
			  const struct initcall *begin,
			  const struct initcall *end)
{
	const struct initcall *call = NULL;
	TEE_Result ret = TEE_SUCCESS;

	for (call = begin; call < end; call++) {
		DMSG("%s level %d %s()", type, call->level, call->func_name);
		ret = call->func();
		if (ret) {
			EMSG("%s __text_start + 0x%08"PRIxVA" failed",
			     type, (vaddr_t)call - VCORE_START_VA);
		}
	}
}

#define DO_INIT_CALLS(name) \
	do_init_calls(#name, name##_begin, name##_end)

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_preinitcalls(void)
{
	DO_INIT_CALLS(preinitcall);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_early_initcalls(void)
{
	DO_INIT_CALLS(early_initcall);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_service_initcalls(void)
{
	DO_INIT_CALLS(service_initcall);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_driver_initcalls(void)
{
	DO_INIT_CALLS(driver_initcall);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_initcalls(void)
{
	call_early_initcalls();
	call_service_initcalls();
	call_driver_initcalls();
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak call_finalcalls(void)
{
	DO_INIT_CALLS(finalcall);
}
