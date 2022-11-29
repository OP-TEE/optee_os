/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_THREAD_PRIVATE_ARCH_H
#define __KERNEL_THREAD_PRIVATE_ARCH_H

#ifndef __ASSEMBLER__

#include <kernel/thread.h>

#define STACK_TMP_OFFS		0

#if defined(__clang__) && !defined(__OPTIMIZE_SIZE__)
#define STACK_TMP_SIZE		(4096 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#else
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#endif

#define STACK_THREAD_SIZE	(8192 + CFG_STACK_THREAD_EXTRA)

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		1024
#endif

#define STACK_CHECK_EXTRA	0

#endif /*__ASSEMBLER__*/

#ifndef __ASSEMBLER__

extern long thread_user_kcode_offset;

void thread_trap_handler(long cause, unsigned long epc,
			 struct thread_trap_regs *regs,
			 bool core);
/*
 * Initializes TVEC for current hart. Called by thread_init_per_cpu()
 */
void thread_init_tvec(void);
void thread_trap_vect(void);
void thread_trap_vect_end(void);

void thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
uint32_t __thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				uint32_t a3, uint32_t a4, uint32_t a5);

/*
 * Private functions made available for thread_asm.S
 */

void thread_resume(struct thread_ctx_regs *regs);
uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
				  uint32_t *exit_status0,
				  uint32_t *exit_status1);
void *thread_get_tmp_sp(void);
void thread_state_free(void);
struct thread_ctx_regs *thread_get_ctx_regs(void);
void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3);
void thread_svc_handler(struct thread_svc_regs *regs);

#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_PRIVATE_ARCH_H*/
