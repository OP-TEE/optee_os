/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 1994-2009  Red Hat, Inc.
 * Copyright (c) 2016, Linaro Limited
 * Copyright 2022-2023 NXP
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
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
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

#ifndef __SETJMP_H
#define __SETJMP_H

#include <compiler.h>

#if defined(ARM32)
/*
 * All callee preserved registers:
 * v1 - v7, fp, ip, sp, lr, f4, f5, f6, f7
 * One additional 32-bit value used in case ftrace
 * is enabled to restore ftrace return stack.
 */
#define _JBLEN 24
#define _JBTYPE int
#endif

#if defined(ARM64)
#define _JBLEN 22
#define _JBTYPE long long
#endif

#if defined(RV64) || defined(RV32)
/*
 * Callee preserved registers:
 * s0-s11, ra, sp
 * One additional value used in case ftrace
 * is enabled to restore ftrace return stack.
 */
#define _JBLEN 15
#define _JBTYPE unsigned long
#endif

#ifdef _JBLEN
typedef	_JBTYPE jmp_buf[_JBLEN];
#endif

void __noreturn longjmp(jmp_buf env, int val);
int setjmp(jmp_buf env);

#ifdef CFG_FTRACE_SUPPORT
void ftrace_longjmp(unsigned int *ret_idx);
void ftrace_setjmp(unsigned int *ret_idx);
#endif

#endif /*__SETJMP_H*/
