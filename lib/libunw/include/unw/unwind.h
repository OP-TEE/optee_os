/* SPDX-License-Identifier: (BSD-2-Clause AND MIT-CMU) */
/*-
 * Copyright (c) 2023 Andes Technology Corporation
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

#ifndef UNW_UNWIND_H
#define UNW_UNWIND_H

#include <compiler.h>
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

#ifdef CFG_UNWIND
/*
 * Unwind a 32-bit stack.
 * @stack, @stack_size: the bottom of the stack and its size, respectively.
 * Returns false when there is nothing more to unwind.
 */
bool unwind_stack_arm32(struct unwind_state_arm32 *state,
			vaddr_t stack, size_t stack_size);

void print_stack_arm32(struct unwind_state_arm32 *state,
		       vaddr_t stack, size_t stack_size);
#else
static inline bool unwind_stack_arm32(struct unwind_state_arm32 *state __unused,
				      vaddr_t stack __unused,
				      size_t stack_size __unused)
{
	return false;
}

static inline void print_stack_arm32(struct unwind_state_arm32 *state __unused,
				     vaddr_t stack __unused,
				     size_t stack_size __unused)
{
}
#endif

/*
 * External helper function. Must be implemented by the caller of the 32-bit
 * stack unwinding functions.
 */
bool find_exidx(vaddr_t addr, vaddr_t *idx_start, vaddr_t *idx_end);

/* The state of the unwind process (64-bit mode) */
struct unwind_state_arm64 {
	uint64_t fp;
	uint64_t sp;
	uint64_t pc;
};

#if defined(ARM64) && defined(CFG_UNWIND)
/*
 * Unwind a 64-bit stack.
 * @stack, @stack_size: the bottom of the stack and its size, respectively.
 * Returns false when there is nothing more to unwind.
 */
bool unwind_stack_arm64(struct unwind_state_arm64 *state,
			vaddr_t stack, size_t stack_size);

void print_stack_arm64(struct unwind_state_arm64 *state,
		       vaddr_t stack, size_t stack_size);
#else
static inline bool unwind_stack_arm64(struct unwind_state_arm64 *state __unused,
				      vaddr_t stack __unused,
				      size_t stack_size __unused)
{
	return false;
}

static inline void print_stack_arm64(struct unwind_state_arm64 *state __unused,
				     vaddr_t stack __unused,
				     size_t stack_size __unused)
{
}
#endif

/* The state of the unwind process */
struct unwind_state_riscv {
	unsigned long fp;
	unsigned long pc;
};

#if (defined(RV32) || defined(RV64)) && defined(CFG_UNWIND)
/*
 * Unwind stack.
 * @stack, @stack_size: the bottom of the stack and its size, respectively.
 * Returns false when there is nothing more to unwind.
 */
bool unwind_stack_riscv(struct unwind_state_riscv *state,
			vaddr_t stack, size_t stack_size);

void print_stack_riscv(struct unwind_state_riscv *state,
		       vaddr_t stack, size_t stack_size);
#else
static inline bool unwind_stack_riscv(struct unwind_state_riscv *state __unused,
				      vaddr_t stack __unused,
				      size_t stack_size __unused)
{
	return false;
}

static inline void print_stack_riscv(struct unwind_state_riscv *state __unused,
				     vaddr_t stack __unused,
				     size_t stack_size __unused)
{
}
#endif

/*
 * External helper function optionally implemented by the caller of the 64-bit
 * stack unwinding functions.
 */
void ftrace_map_lr(uint64_t *lr);

/* Strip out PAuth tags from LR content if applicable */
void pauth_strip_pac(uint64_t *lr);

#endif /*UNW_UNWIND_H*/
