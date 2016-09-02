/*-
 * Copyright (c) 2015, Linaro Limited
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

#ifndef KERNEL_UNWIND
#define KERNEL_UNWIND

#ifndef ASM
#include <types_ext.h>

#ifdef ARM32
/* The state of the unwind process */
struct unwind_state {
	uint32_t registers[16];
	uint32_t start_pc;
	uint32_t *insn;
	unsigned entries;
	unsigned byte;
	uint16_t update_mask;
};
#endif /*ARM32*/

#ifdef ARM64
struct unwind_state {
	uint64_t fp;
	uint64_t sp;
	uint64_t pc;
};
#endif /*ARM64*/

bool unwind_stack(struct unwind_state *state);

#if defined(CFG_CORE_UNWIND) && (TRACE_LEVEL > 0)
void print_stack(int level);
#else
static inline void print_stack(int level __unused)
{
}
#endif

#endif /*ASM*/

#ifdef CFG_CORE_UNWIND
#define UNWIND(...)	__VA_ARGS__
#else
#define UNWIND(...)
#endif

#endif /*KERNEL_UNWIND*/
