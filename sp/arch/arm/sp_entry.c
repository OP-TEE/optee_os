// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */

#include <stddef.h>
#include <stdint.h>
#include "compiler.h"
#include "optee_sp_internal_api.h"
#include "optee_sp_user_defines.h"
#include "malloc.h"

/* Allocating heap area */
#ifndef OPTEE_SP_HEAP_SIZE
#error "OPTEE_SP_HEAP_SIZE is not defined in SP"
#endif

uint8_t sp_heap[OPTEE_SP_HEAP_SIZE] __aligned(16);
const size_t sp_heap_size = sizeof(sp_heap);

#ifdef ARM32
#define _C_FUNCTION(name) name##_c
#else
#define _C_FUNCTION(name) name
#endif /* ARM32 */

/*
 * According to the FF-A specification an optional initialization descriptor can
 * be passed to the SP in w0/x0-w3/x3 registers (a0-a3 parameters). As the exact
 * register is implementation defined the first four registers are forwarded to
 * the user code.
 */
void __noreturn _C_FUNCTION(__sp_entry)(uintptr_t a0, uintptr_t a1,
					uintptr_t a2, uintptr_t a3);
void __noreturn _C_FUNCTION(__sp_entry)(uintptr_t a0, uintptr_t a1,
					uintptr_t a2, uintptr_t a3)
{
	/* Initializing heap */
	malloc_add_pool(sp_heap, sp_heap_size);

	/* Forwarding call to user code. */
	optee_sp_entry(a0, a1, a2, a3);
}
