#ifndef __KEEP_INIT_H
#define __KEEP_INIT_H

#include <compiler.h>

#define __DECLARE_KEEP_INIT2(sym, file_id) \
	extern const unsigned long ____keep_init_##sym##file_id; \
	const unsigned long ____keep_init_##sym##_##file_id \
		__section("__keep_meta_vars_init") = (unsigned long)&(sym)

#define __DECLARE_KEEP_INIT1(sym, file_id) __DECLARE_KEEP_INIT2(sym, file_id)
#define DECLARE_KEEP_INIT(sym) __DECLARE_KEEP_INIT1(sym, __FILE_ID__)

#endif /* __KEEP_INIT_H */
