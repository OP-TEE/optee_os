/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2022, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */
#ifndef __KERNEL_ARCH_SCALL_H
#define __KERNEL_ARCH_SCALL_H

#include <arm.h>
#include <kernel/thread.h>
#include <types_ext.h>

static inline void scall_get_max_args(struct thread_scall_regs *regs,
				      size_t *scn, size_t *max_args)
{
#ifdef ARM32
	*scn = regs->r7;
	*max_args = regs->r6;
#endif
#ifdef ARM64
	if (((regs->spsr >> SPSR_MODE_RW_SHIFT) & SPSR_MODE_RW_MASK) ==
	     SPSR_MODE_RW_32) {
		*scn = regs->x7;
		*max_args = regs->x6;
	} else {
		*scn = regs->x8;
		*max_args = 0;
	}
#endif
}

static inline void scall_set_retval(struct thread_scall_regs *regs,
				    uint32_t ret_val)
{
#ifdef ARM32
	regs->r0 = ret_val;
#endif
#ifdef ARM64
	regs->x0 = ret_val;
#endif
}

static inline void scall_set_sys_return_regs(struct thread_scall_regs *regs,
					     bool panic, uint32_t panic_code)
{
#ifdef ARM32
	regs->r1 = panic;
	regs->r2 = panic_code;
#endif
#ifdef ARM64
	regs->x1 = panic;
	regs->x2 = panic_code;
#endif
}
#endif /*__KERNEL_ARCH_SCALL_H*/

