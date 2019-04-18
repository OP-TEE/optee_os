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
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <sm/tee_mon.h>
#include <tee/tee_fs.h>
#include <tee/tee_svc.h>
#include <trace.h>

#include <platform_config.h>


#define TEE_MON_MAX_NUM_ARGS    8

static void call_initcalls(void)
{
	const initcall_t *call;

	for (call = initcall_begin; call < initcall_end; call++) {
		TEE_Result ret;
		ret = (*call)();
		if (ret != TEE_SUCCESS) {
			EMSG("Initial call 0x%08" PRIxVA " failed",
			     (vaddr_t)call);
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

#ifdef CFG_WITH_USER_TA
	tee_svc_uref_base = TEE_TEXT_VA_START;
#endif

#ifdef CFG_CORE_RESERVED_SHM
	/* init support for future mapping of TAs */
	teecore_init_pub_ram();
#endif

	/* time initialization */
	time_source_init();

	/* call pre-define initcall routines */
	call_initcalls();

	/*
	 * Now that RNG is initialized generate the key needed for r/w
	 * paging.
	 */
	tee_pager_generate_authenc_key();

	IMSG("Initialized");
	return TEE_SUCCESS;
}
