/*
 * Copyright (c) 2016, Linaro Limited
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

#ifndef SM_SM_H
#define SM_SM_H

#include <compiler.h>
#include <types_ext.h>

struct sm_mode_regs {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t irq_spsr;
	uint32_t irq_sp;
	uint32_t irq_lr;
	uint32_t fiq_spsr;
	uint32_t fiq_sp;
	uint32_t fiq_lr;
	/*
	 * Note that fiq_r{8-12} are not saved here. Instead thread_fiq_handler
	 * preserves r{8-12}.
	 */
	uint32_t svc_spsr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t abt_spsr;
	uint32_t abt_sp;
	uint32_t abt_lr;
	uint32_t und_spsr;
	uint32_t und_sp;
	uint32_t und_lr;
};

struct sm_nsec_ctx {
	struct sm_mode_regs mode_regs;

	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;

	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;

	/* return state */
	uint32_t mon_lr;
	uint32_t mon_spsr;
};

struct sm_sec_ctx {
	struct sm_mode_regs mode_regs;

	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;

	/* return state */
	uint32_t mon_lr;
	uint32_t mon_spsr;
};

struct sm_ctx {
	uint32_t pad;
	struct sm_sec_ctx sec;
	struct sm_nsec_ctx nsec;
};

/*
 * The secure monitor reserves space at top of stack_tmp to hold struct
 * sm_ctx.
 */
#define SM_STACK_TMP_RESERVE_SIZE	sizeof(struct sm_ctx)



/* Returns storage location of non-secure context for current CPU */
struct sm_nsec_ctx *sm_get_nsec_ctx(void);

/* Returns stack pointer to use in monitor mode for current CPU */
void *sm_get_sp(void);

/*
 * Initializes secure monitor, must be called by each CPU
 */
void sm_init(vaddr_t stack_pointer);

#ifndef CFG_SM_PLATFORM_HANDLER
/*
 * Returns false if we handled the monitor service and should now return
 * back to the non-secure state
 */
static inline bool sm_platform_handler(__unused struct sm_ctx *ctx)
{
	return true;
}
#else
bool sm_platform_handler(struct sm_ctx *ctx);
#endif

#endif /*SM_SM_H*/
