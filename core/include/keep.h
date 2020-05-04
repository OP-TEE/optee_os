/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef KEEP_H
#define KEEP_H

#ifdef __ASSEMBLER__

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

#define __KEEP_PAGER2(sym, file_id) \
	extern const unsigned long ____keep_pager_##sym; \
	const unsigned long ____keep_pager_##sym##_##file_id  \
		__section("__keep_meta_vars_pager") = (unsigned long)&(sym)

#define __KEEP_PAGER1(sym, file_id)	__KEEP_PAGER2(sym, file_id)
#define KEEP_PAGER(sym)			__KEEP_PAGER1(sym, __FILE_ID__)

#define __KEEP_INIT2(sym, file_id) \
	extern const unsigned long ____keep_init_##sym##file_id; \
	const unsigned long ____keep_init_##sym##_##file_id  \
		__section("__keep_meta_vars_init") = (unsigned long)&(sym)

#define __KEEP_INIT1(sym, file_id)	__KEEP_INIT2(sym, file_id)
#define KEEP_INIT(sym)			__KEEP_INIT1(sym, __FILE_ID__)

#endif /* __ASSEMBLER__ */

#endif /*KEEP_H*/
