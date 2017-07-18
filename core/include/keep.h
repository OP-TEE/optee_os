/*
 * Copyright (c) 2015, Linaro Limited
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
#ifndef KEEP_H
#define KEEP_H

#ifdef ASM

	.macro KEEP_PAGER sym
	.pushsection __keep_meta_vars_pager
	.global ____keep_pager_\sym
	____keep_pager_\sym:
	.long	\sym
	.popsection
	.endm

	.macro KEEP_INIT sym
	.pushsection __keep_meta_vars_init
	.global ____keep_init_\sym
	____keep_init_\sym:
	.long	\sym
	.popsection
	.endm

#else

#include <compiler.h>

#define KEEP_PAGER(sym) \
	extern const unsigned long ____keep_pager_##sym; \
	const unsigned long ____keep_pager_##sym  \
		__section("__keep_meta_vars_pager") = (unsigned long)&sym

#define KEEP_INIT(sym) \
	extern const unsigned long ____keep_init_##sym; \
	const unsigned long ____keep_init_##sym  \
		__section("__keep_meta_vars_init") = (unsigned long)&sym

#endif /* ASM */

#endif /*KEEP_H*/
