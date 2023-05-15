/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */

#ifndef KERNEL_ABORT_H
#define KERNEL_ABORT_H

#define ABORT_TYPE_UNDEF		0
#define ABORT_TYPE_PREFETCH		1
#define ABORT_TYPE_DATA			2
/* Dump stack on user mode panic (not an abort) */
#define ABORT_TYPE_USER_MODE_PANIC	3

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <types_ext.h>

struct abort_info {
	uint32_t abort_type;
	uint32_t fault_descr;	/* only valid for data of prefetch abort */
	vaddr_t va;
	uint32_t pc;
	struct thread_abort_regs *regs;
};

/* Print abort info to the console */
void abort_print(struct abort_info *ai);
/* Print abort info + stack dump to the console */
void abort_print_error(struct abort_info *ai);

void abort_handler(uint32_t abort_type, struct thread_abort_regs *regs);

bool abort_is_user_exception(struct abort_info *ai);

bool abort_is_write_fault(struct abort_info *ai);

/* Called from a normal thread */
void abort_print_current_ts(void);

#endif /*__ASSEMBLER__*/
#endif /*KERNEL_ABORT_H*/

