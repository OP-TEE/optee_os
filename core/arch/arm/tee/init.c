// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <initcall.h>
#include <kernel/linker.h>
#include <kernel/tee_misc.h>
#include <kernel/time_source.h>
#include <malloc.h>		/* required for inits */
#include <mm/core_memprot.h>
#include <mm/fobj.h>
#include <mm/tee_mmu.h>
#include <sm/tee_mon.h>
#include <tee/tee_fs.h>
#include <tee/tee_svc.h>
#include <trace.h>

#include <platform_config.h>


#define TEE_MON_MAX_NUM_ARGS    8

static void call_initcalls(void)
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
TEE_Result __weak init_teecore(void)
{
	static int is_first = 1;

	/* (DEBUG) for inits at 1st TEE service: when UART is setup */
	if (!is_first)
		return TEE_SUCCESS;
	is_first = 0;

	/* call pre-define initcall routines */
	call_initcalls();

	/*
	 * Now that RNG is initialized generate the key needed for r/w
	 * paging.
	 */
	fobj_generate_authenc_key();

	IMSG("Initialized");
	return TEE_SUCCESS;
}
