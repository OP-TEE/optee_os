/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <asm.S>

/*
 * This assembly source is used both in kernel and userland
 * hence define unwind resources that match both environments.
 */
#if defined(CFG_UNWIND)
#define LOCAL_UNWIND(...)	__VA_ARGS__
#else
#define LOCAL_UNWIND(...)
#endif

/*
 * signed ret_idivmod_values(signed quot, signed rem);
 * return quotient and remaining the EABI way (regs r0,r1)
 */
.section .text.ret_idivmod_values
FUNC ret_idivmod_values , :
LOCAL_UNWIND(.fnstart)
        bx lr
LOCAL_UNWIND(.fnend)
END_FUNC ret_idivmod_values

/*
 * unsigned ret_uidivmod_values(unsigned quot, unsigned rem);
 * return quotient and remaining the EABI way (regs r0,r1)
 */
.section .text.ret_uidivmod_values
FUNC ret_uidivmod_values , :
LOCAL_UNWIND(.fnstart)
        bx      lr
LOCAL_UNWIND(.fnend)
END_FUNC ret_uidivmod_values
