/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_THREAD_ARCH_H
#define __KERNEL_THREAD_ARCH_H

#ifndef __ASSEMBLER__
#include <riscv.h>
#include <types_ext.h>
#include <compiler.h>
#endif

#ifndef __ASSEMBLER__

#define THREAD_CORE_LOCAL_ALIGNED __aligned(2 * RISCV_XLEN_BYTES)

struct thread_core_local {
	uint64_t x[4];
	vaddr_t tmp_stack_va_end;
	short int curr_thread;
	uint32_t flags;
	vaddr_t abt_stack_va_end;
#ifdef CFG_TEE_CORE_DEBUG
	unsigned int locked_count; /* Number of spinlocks held */
#endif
#ifdef CFG_CORE_DEBUG_CHECK_STACKS
	bool stackcheck_recursion;
#endif
} THREAD_CORE_LOCAL_ALIGNED;


struct thread_abort_regs {
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long epc;
	unsigned long status;
};

struct thread_ctx_regs {
	unsigned long ra;
	unsigned long sp;
	unsigned long fp;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long status;
};

struct thread_trap_frame {
	unsigned long sp;
	unsigned long ra;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long epc;
	unsigned long status;
};

struct user_mode_ctx;

/*
 * Defines the bits for the exception mask used by the
 * thread_*_exceptions() functions below.
 * These definitions are for targets running U/M modes. Consider external
 * interrupts as foreign interrupts for now.
 */

#define THREAD_EXCP_FOREIGN_INTR (MIP_UEIP | MIP_MEIP)
#define THREAD_EXCP_NATIVE_INTR  (MIP_USIP | MIP_MSIP | MIP_UTIP | MIP_MTIP)

#define THREAD_EXCP_ALL	(THREAD_EXCP_FOREIGN_INTR | \
						 THREAD_EXCP_NATIVE_INTR)
					
static inline void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}

static inline void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}

static inline void thread_kernel_restore_vfp(void)
{
}

static inline void thread_user_save_vfp(void)
{
}

static inline void thread_user_clear_vfp(struct user_mode_ctx *uctx __unused)
{
}
					
#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_ARCH_H*/
