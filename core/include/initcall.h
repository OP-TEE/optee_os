/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef INITCALL_H
#define INITCALL_H

#include <scattered_array.h>
#include <tee_api_types.h>
#include <trace.h>

struct initcall {
	TEE_Result (*func)(void);
#if TRACE_LEVEL >= TRACE_DEBUG
	int level;
	const char *func_name;
#endif
};

#if TRACE_LEVEL >= TRACE_DEBUG
#define __define_initcall(lvl, fn) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(initcall, lvl, \
					       struct initcall) = \
		{ .func = (fn), .level = (lvl), .func_name = #fn, }
#else
#define __define_initcall(lvl, fn) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(initcall, lvl, \
					       struct initcall) = \
		{ .func = (fn), }
#endif

#define initcall_begin	SCATTERED_ARRAY_BEGIN(initcall, struct initcall)
#define initcall_end	SCATTERED_ARRAY_END(initcall, struct initcall)

#define early_init(fn)			__define_initcall(1, fn)
#define early_init_late(fn)		__define_initcall(2, fn)
#define service_init(fn)		__define_initcall(3, fn)
#define service_init_late(fn)		__define_initcall(4, fn)
#define driver_init(fn)			__define_initcall(5, fn)
#define driver_init_late(fn)		__define_initcall(6, fn)

void call_initcalls(void);

#endif
