/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */

#ifndef SP_INCLUDE_OPTEE_SP_INTERNAL_API_H_
#define SP_INCLUDE_OPTEE_SP_INTERNAL_API_H_

#include <stddef.h>
#include <stdint.h>
#include "compiler.h"
#include "util.h"

/*
 * The file describes the API between the SP dev kit and the SP. It contains the
 * function prototypes that the user code must define.
 * The SP code base should also contain a header file named
 * "optee_sp_user_defines.h" for passing the following definitions to the SP dev
 * kit:
 * * OPTEE_SP_HEAP_SIZE: Heap size in bytes
 * * OPTEE_SP_UUID: UUID of the SP as an sp_uuid structure
 * * OPTEE_SP_STACK_SIZE: Stack size in bytes
 */

/*
 * The file defines the functions and variables that other
 */

/*
 * SP header types
 */
struct optee_sp_uuid {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
};

struct optee_sp_head {
	struct optee_sp_uuid uuid;
	uint32_t stack_size;
	uint32_t flags;
	uint64_t depr_entry;
};

/*
 * The function is the entry point of the SP.
 * According to the FF-A specification an optional initialization descriptor can
 * be passed to the SP in w0/x0-w3/x3 registers (a0-a3 parameters). As the exact
 * register is implementation defined the first four registers are forwarded to
 * the user code.
 */
void __noreturn optee_sp_entry(uintptr_t a0, uintptr_t a1, uintptr_t a2,
			       uintptr_t a3);

/*
 * User defined logging function.
 */
void optee_sp_log_puts(const char *str);

/*
 * User defined panic function.
 */
void __noreturn optee_sp_panic(void);

#endif /* SP_INCLUDE_OPTEE_SP_INTERNAL_API_H_ */
