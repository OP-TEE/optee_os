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

#ifndef COMPILER_H
#define COMPILER_H

/*
 * Macros that should be used instead of using __attributue__ directly to
 * ease portability and make the code easier to read.
 */

#define __deprecated	__attribute__((deprecated))
#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))
#define __noreturn	__attribute__((noreturn))
#define __pure		__attribute__((pure))
#define __aligned(x)	__attribute__((aligned(x)))
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define __noinline	__attribute__((noinline))
#define __attr_const	__attribute__((__const__))
#define __unused	__attribute__((unused))
#define __maybe_unused	__attribute__((unused))
#define __used		__attribute__((__used__))
#define __must_check	__attribute__((warn_unused_result))
#define __cold		__attribute__((__cold__))
#define __section(x)	__attribute__((section(x)))
#define __data		__section(".data")
#define __bss		__section(".bss")
#define __rodata	__section(".rodata")
#define __rodata_unpaged __section(".rodata.__unpaged")

#endif /*COMPILER_H*/
