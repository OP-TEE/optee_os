/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef FTRACE_H
#define FTRACE_H

#include <types_ext.h>
#include <user_ta_header.h>

#ifdef CFG_FTRACE_SUPPORT
bool ftrace_init(struct ftrace_buf **fbuf_ptr);
void ftrace_copy_buf(void *pctx, void (*copy_func)(void *pctx, void *b,
						   size_t bl));
void ftrace_map_lr(uint64_t *lr);
#else
static inline void ftrace_map_lr(uint64_t *lr __unused)
{
}
#endif

#endif /*FTRACE_H*/

