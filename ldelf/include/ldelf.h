/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __LDELF_H
#define __LDELF_H

#include <stdint.h>
#include <tee_api_types.h>

/* Size of stack for TEE Core to allocate */
#define LDELF_STACK_SIZE	(4096 * 2)

/*
 * struct ldelf_arg - argument for ldelf
 * @uuid:	[in] UUID of TA to load
 * @is_32bit:	[out] 1 if a 32bit TA or 0 if a 64bit TA
 * @flags:	[out] Flags field of TA header
 * @entry_func:	[out] TA entry function
 * @stack_ptr:	[out] TA stack pointer
 */
struct ldelf_arg {
	TEE_UUID uuid;
	uint32_t is_32bit;
	uint32_t flags;
	uint64_t entry_func;
	uint64_t stack_ptr;
};

/*
 * ldelf is loaded into memory by TEE Core. BSS is initialized and a
 * stack is allocated and supplied in SP register. A struct ldelf_arg
 * is placed in the stack and a pointer to the struct is provided in
 * r0/x0.
 *
 * ldelf relocates itself to the address where it is loaded before the main
 * C routine is called.
 *
 * In the main C routine the TA is loaded using the PTA System interface.
 */

#endif /*__LDELF_H*/
