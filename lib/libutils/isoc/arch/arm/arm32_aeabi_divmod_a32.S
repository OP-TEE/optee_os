/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
