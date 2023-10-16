/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __KERNEL_MISC_H
#define __KERNEL_MISC_H

#include <assert.h>
#include <kernel/misc_arch.h>
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

#endif /*__KERNEL_MISC_H*/
