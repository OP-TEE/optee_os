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
#define __define_initcall(type, lvl, fn) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(type ## call, lvl, \
					       struct initcall) = \
		{ .func = (fn), .level = (lvl), .func_name = #fn, }
#else
#define __define_initcall(type, lvl, fn) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(type ## call, lvl, \
					       struct initcall) = \
		{ .func = (fn), }
#endif

#define initcall_begin	SCATTERED_ARRAY_BEGIN(initcall, struct initcall)
#define initcall_end	SCATTERED_ARRAY_END(initcall, struct initcall)

#define finalcall_begin	SCATTERED_ARRAY_BEGIN(finalcall, struct initcall)
#define finalcall_end	SCATTERED_ARRAY_END(finalcall, struct initcall)

#define early_init(fn)			__define_initcall(init, 1, fn)
#define early_init_late(fn)		__define_initcall(init, 2, fn)
#define service_init(fn)		__define_initcall(init, 3, fn)
#define service_init_late(fn)		__define_initcall(init, 4, fn)
#define driver_init(fn)			__define_initcall(init, 5, fn)
#define driver_init_late(fn)		__define_initcall(init, 6, fn)

#define boot_final(fn)			__define_initcall(final, 1, fn)

void call_initcalls(void);
void call_finalcalls(void);

#endif
