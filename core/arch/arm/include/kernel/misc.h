/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef KERNEL_MISC_H
#define KERNEL_MISC_H

#include <arm.h>
#include <assert.h>
#include <kernel/thread.h>
#include <types_ext.h>

size_t __get_core_pos(void);

static inline size_t __noprof get_core_pos(void)
{
	/*
	 * Foreign interrupts must be disabled before playing with current
	 * core since we otherwise may be rescheduled to a different core.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	return __get_core_pos();
}

size_t get_core_pos_mpidr(uint32_t mpidr);

uint32_t read_mode_sp(int cpu_mode);
uint32_t read_mode_lr(int cpu_mode);

void wait_cycles(unsigned long cycles);

#endif /*KERNEL_MISC_H*/

