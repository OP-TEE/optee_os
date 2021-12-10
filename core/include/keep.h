/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef KEEP_H
#define KEEP_H

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

/*
 * DECLARE_KEEP_PAGER() - Resource and its dependencies are linked in
 * an unpaged section
 */
#define DECLARE_KEEP_PAGER(sym) __DECLARE_KEEP_PAGER1(sym, __FILE_ID__)

#define __DECLARE_KEEP_INIT2(sym, file_id) \
	extern const unsigned long ____keep_init_##sym##file_id; \
	const unsigned long ____keep_init_##sym##_##file_id  \
		__section("__keep_meta_vars_init") = (unsigned long)&(sym)

#define __DECLARE_KEEP_INIT1(sym, file_id) __DECLARE_KEEP_INIT2(sym, file_id)

/*
 * DECLARE_KEEP_INIT() - Resource and its dependencies are linked in
 * an init (a.k.a pageable pre-mapped) section
 */
#define DECLARE_KEEP_INIT(sym) __DECLARE_KEEP_INIT1(sym, __FILE_ID__)

/*
 * DEFINE_RODATA_UNPAGED() - Define a read-only unpaged variable
 *
 * Define a const variable linked into an unpaged read-only section without
 * propagating its unpaged constrain to the references the variable may refer
 * to. This requires defining it twice with specific attributes for pager
 * linker management. The variable is global (not static) since using __weak
 * attribute for the dual definition.
 */
#define DEFINE_RODATA_UNPAGED(_type, _label) \
	const _type _label __rodata_dummy; \
	const _type _label __weak __rodata_unpaged(#_label)

#endif /* __ASSEMBLER__ */

#endif /*KEEP_H*/
