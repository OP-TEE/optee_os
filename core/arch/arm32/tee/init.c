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
#include <assert.h>
#include <malloc.h>		/* required for inits */

#include <sm/tee_mon.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <kernel/tee_core_trace.h>
#include <kernel/time_source.h>
#include <mm/tee_mmu.h>
#include <tee/tee_fs.h>
#include <tee/tee_cryp_provider.h>



#ifndef WITH_UART_DRV
#include <kernel/asc.h>
#endif

#define TEE_MON_MAX_NUM_ARGS    8

TEE_Result init_teecore(void)
{
	static int is_first = 1;
	unsigned long a, s;

	/* (DEBUG) for inits at 1st TEE service: when UART is setup */
	if (!is_first)
		return TEE_SUCCESS;
	is_first = 0;

#ifndef WITH_UART_DRV
	/* UART tracing support */
	asc_init();
	IMSG("teecore: uart trace init");
#endif

	/* core malloc pool init */
#ifdef CFG_TEE_MALLOC_START
	a = CFG_TEE_MALLOC_START;
	s = CFG_TEE_MALLOC_SIZE;
#else
	a = (unsigned long)&teecore_heap_start;
	s = (unsigned long)&teecore_heap_end;
	a = ((a + 1) & ~0x0FFFF) + 0x10000;	/* 64kB aligned */
	s = s & ~0x0FFFF;	/* 64kB aligned */
	s = s - a;
#endif
	IMSG("teecore heap: paddr=0x%lX size=0x%lX (%ldkB)", a, s, s / 1024);
	malloc_init((void *)a, s);

	/* init support for futur mapping of TAs */
	tee_mmu_kmap_init();
	teecore_init_ta_ram();
	teecore_init_pub_ram();

	/* Initialize cryptographic provider */
	tee_cryp_init();

	/* time initialization */
	time_source_init();

	IMSG("teecore inits done");
	return TEE_SUCCESS;
}

TEE_Result tee_cryp_init(void)
{
	if (crypto_ops.init)
		return crypto_ops.init();

	return TEE_SUCCESS;
}
