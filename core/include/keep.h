/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef __KEEP_H
#define __KEEP_H

#ifdef __ASSEMBLER__

	.macro DECLARE_KEEP_PAGER sym
	.pushsection __keep_meta_vars_pager, "a"
	.global ____keep_pager_\sym
	____keep_pager_\sym:
	.long	\sym
	.popsection
	.endm

	.macro DECLARE_KEEP_INIT sym
	.pushsection __keep_meta_vars_init, "a"
	.global ____keep_init_\sym
	____keep_init_\sym:
	.long	\sym
	.popsection
	.endm

#else

#include <compiler.h>

#define __DECLARE_KEEP_PAGER2(sym, file_id) \
	extern const unsigned long ____keep_pager_##sym; \
	const unsigned long ____keep_pager_##sym##_##file_id  \
		__section("__keep_meta_vars_pager") = (unsigned long)&(sym)

#define __DECLARE_KEEP_PAGER1(sym, file_id) __DECLARE_KEEP_PAGER2(sym, file_id)
#define DECLARE_KEEP_PAGER(sym) __DECLARE_KEEP_PAGER1(sym, __FILE_ID__)

#define __DECLARE_KEEP_INIT2(sym, file_id) \
	extern const unsigned long ____keep_init_##sym##file_id; \
	const unsigned long ____keep_init_##sym##_##file_id  \
		__section("__keep_meta_vars_init") = (unsigned long)&(sym)

#define __DECLARE_KEEP_INIT1(sym, file_id) __DECLARE_KEEP_INIT2(sym, file_id)
#define DECLARE_KEEP_INIT(sym) __DECLARE_KEEP_INIT1(sym, __FILE_ID__)

#endif /* __ASSEMBLER__ */

#endif /*__KEEP_H*/
