/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef FTRACE_H
#define FTRACE_H

#include <types_ext.h>

bool ftrace_init(void);
void ftrace_copy_buf(void *pctx, void (*copy_func)(void *pctx, void *b,
						   size_t bl));
#ifdef CFG_TA_FTRACE_SUPPORT
void ftrace_map_lr(uint64_t *lr);
#else
static inline void ftrace_map_lr(uint64_t *lr __unused)
{
}
#endif

#endif /*FTRACE_H*/

