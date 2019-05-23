/*-
 * Copyright (c) 2015-2019, Linaro Limited
 * Copyright (c) 2000, 2001 Ben Harris
 * Copyright (c) 1996 Scott K. Stevens
 *
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 * $FreeBSD$
 */

#ifndef UNWIND_H
#define UNWIND_H

#include <compiler.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* The state of the unwind process (32-bit mode) */
struct unwind_state_arm32 {
	uint32_t registers[16];
	uint32_t start_pc;
	vaddr_t insn;
	unsigned int entries;
	unsigned int byte;
	uint16_t update_mask;
};

void print_stack_arm32(struct unwind_state_arm32 *state,
		       vaddr_t stack, size_t stack_size);

/* The state of the unwind process (64-bit mode) */
struct unwind_state_arm64 {
	uint64_t fp;
	uint64_t sp;
	uint64_t pc;
};

void print_stack_arm64(struct unwind_state_arm64 *state,
		       vaddr_t stack, size_t stack_size);

#endif /*UNWIND_H*/
