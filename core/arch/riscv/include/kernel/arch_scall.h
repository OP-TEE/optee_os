/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KERNEL_ARCH_SCALL_H
#define __KERNEL_ARCH_SCALL_H

#include <kernel/thread.h>
#include <riscv.h>
#include <types_ext.h>

static inline void scall_get_max_args(struct thread_scall_regs *regs,
				      size_t *scn, size_t *max_args)
{
	*scn = regs->t0;
	*max_args = regs->t1;
}

static inline void scall_set_retval(struct thread_scall_regs *regs,
				    uint32_t ret_val)
{
	regs->a0 = ret_val;
}

static inline void scall_set_sys_return_regs(struct thread_scall_regs *regs,
					     bool panic, uint32_t panic_code)
{
	regs->a1 = panic;
	regs->a2 = panic_code;
}

#endif /*__KERNEL_ARCH_SCALL_H*/
