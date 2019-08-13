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
#include <compiler.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* The state of the unwind process (32-bit mode) */
struct unwind_state_arm32 {
	uint32_t registers[16];
	uint32_t start_pc;
	vaddr_t insn;
	unsigned entries;
	unsigned byte;
	uint16_t update_mask;
};

/*
 * Unwind a 32-bit user or kernel stack.
 * @exidx, @exidx_sz: address and size of the binary search index table
 * (.ARM.exidx section).
 * @stack, @stack_size: the bottom of the stack and its size, respectively.
 */
bool unwind_stack_arm32(struct unwind_state_arm32 *state, vaddr_t exidx,
			size_t exidx_sz, vaddr_t stack, size_t stack_size);

#ifdef ARM64
/* The state of the unwind process (64-bit mode) */
struct unwind_state_arm64 {
	uint64_t fp;
	uint64_t sp;
	uint64_t pc;
};

/*
 * Unwind a 64-bit kernel stack.
 * @stack, @stack_size: the bottom of the stack and its size, respectively.
 */
bool unwind_stack_arm64(struct unwind_state_arm64 *state,
			vaddr_t stack, size_t stack_size);
#endif /*ARM64*/

#if defined(CFG_UNWIND) && (TRACE_LEVEL > 0)

#ifdef ARM64
void print_stack_arm64(int level, struct unwind_state_arm64 *state,
		       vaddr_t stack, size_t stack_size);
#endif
void print_stack_arm32(int level, struct unwind_state_arm32 *state,
		       vaddr_t exidx, size_t exidx_sz,
		       vaddr_t stack, size_t stack_size);
void print_kernel_stack(int level);

#else /* defined(CFG_UNWIND) && (TRACE_LEVEL > 0) */

#ifdef ARM64
static inline void print_stack_arm64(int level __unused,
				     struct unwind_state_arm64 *state __unused,
				     vaddr_t stack __unused,
				     size_t stack_size __unused)
{
}
#endif
static inline void print_stack_arm32(int level __unused,
				     struct unwind_state_arm32 *state __unused,
				     uaddr_t exidx __unused,
				     size_t exidx_sz __unused,
				     vaddr_t stack __unused,
				     size_t stack_size __unused)
{
}
static inline void print_kernel_stack(int level __unused)
{
}

#endif /* defined(CFG_UNWIND) && (TRACE_LEVEL > 0) */

#ifdef CFG_UNWIND
TEE_Result relocate_exidx(void *exidx, size_t exidx_sz, int32_t offset);
/* Get current call stack as an array allocated on the heap */
vaddr_t *unw_get_kernel_stack(void);
#else
static inline TEE_Result relocate_exidx(void *exidx __unused,
					size_t exidx_sz __unused,
					int32_t offset __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
static inline void *unw_get_kernel_stack(void)
{
	return NULL;
}
#endif /* CFG_UNWIND  */

#endif /*ASM*/

#ifdef CFG_UNWIND
#define UNWIND(...)	__VA_ARGS__
#else
#define UNWIND(...)
#endif

#endif /*KERNEL_UNWIND*/
