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

#define preinitcall_begin \
			SCATTERED_ARRAY_BEGIN(preinitcall, struct initcall)
#define preinitcall_end SCATTERED_ARRAY_END(preinitcall, struct initcall)

#define initcall_begin	SCATTERED_ARRAY_BEGIN(initcall, struct initcall)
#define initcall_end	SCATTERED_ARRAY_END(initcall, struct initcall)

#define finalcall_begin	SCATTERED_ARRAY_BEGIN(finalcall, struct initcall)
#define finalcall_end	SCATTERED_ARRAY_END(finalcall, struct initcall)

/*
 * The preinit_*(), *_init() and boot_final() macros are used to register
 * callback functions to be called at different stages during
 * initialization.
 *
 * Functions registered with preinit_*() are always called before functions
 * registered with *_init().
 *
 * Functions registered with boot_final() are called before exiting to
 * normal world the first time.
 *
 * Without virtualization this happens in the order of the defines below.
 *
 * However, with virtualization things are a bit different. boot_final()
 * functions are called first before exiting to normal world the first
 * time. Functions registered with boot_final() can only operate on the
 * nexus. preinit_*() functions are called early before the first yielding
 * call into the partition, in the newly created partition. *_init()
 * functions are called at the first yielding call.
 *
 *  +-------------------------------+-----------------------------------+
 *  | Without virtualization        | With virtualization               |
 *  +-------------------------------+-----------------------------------+
 *  | At the end of boot_init_primary_late() just before the print:     |
 *  | "Primary CPU switching to normal world boot"                      |
 *  +-------------------------------+-----------------------------------+
 *  | 1. call_preinitcalls()        | In the nexus                      |
 *  | 2. call_initcalls()           +-----------------------------------+
 *  | 3. call_finalcalls()          | 1. call_finalcalls()              |
 *  +-------------------------------+-----------------------------------+
 *  | "Primary CPU switching to normal world boot" is printed           |
 *  +-------------------------------+-----------------------------------+
 *                                  | A guest is created and            |
 *                                  | virt_guest_created() is called.   |
 *                                  | After the partition has been      |
 *                                  | created and activated.            |
 *                                  +-----------------------------------+
 *                                  | 2. call_preinitcalls()            |
 *                                  +-----------------------------------+
 *                                  | When the partition is receiving   |
 *                                  | the first yielding call           |
 *                                  | virt_on_stdcall() is called.      |
 *                                  +-----------------------------------+
 *                                  | 3. call_initcalls()               |
 *                                  +-----------------------------------+
 */

#define preinit_early(fn)		__define_initcall(preinit, 1, fn)
#define preinit(fn)			__define_initcall(preinit, 2, fn)
#define preinit_late(fn)		__define_initcall(preinit, 3, fn)

#define early_init(fn)			__define_initcall(init, 1, fn)
#define early_init_late(fn)		__define_initcall(init, 2, fn)
#define service_init(fn)		__define_initcall(init, 3, fn)
#define service_init_late(fn)		__define_initcall(init, 4, fn)
#define driver_init(fn)			__define_initcall(init, 5, fn)
#define driver_init_late(fn)		__define_initcall(init, 6, fn)

#define boot_final(fn)			__define_initcall(final, 1, fn)

void call_preinitcalls(void);
void call_initcalls(void);
void call_finalcalls(void);

#endif
