/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
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
