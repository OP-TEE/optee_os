/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef SM_SM_H
#define SM_SM_H

#include <compiler.h>
#include <types_ext.h>

struct sm_unbanked_regs {
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
#ifdef CFG_SM_NO_CYCLE_COUNTING
	uint32_t pmcr;
#endif
};

struct sm_nsec_ctx {
	struct sm_unbanked_regs ub_regs;

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
	struct sm_unbanked_regs ub_regs;

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
#ifndef CFG_SM_NO_CYCLE_COUNTING
	uint32_t pad;
#endif
	struct sm_sec_ctx sec;
#ifdef CFG_SM_NO_CYCLE_COUNTING
	uint32_t pad;
#endif
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

void sm_save_unbanked_regs(struct sm_unbanked_regs *regs);
void sm_restore_unbanked_regs(struct sm_unbanked_regs *regs);
#endif /*SM_SM_H*/
