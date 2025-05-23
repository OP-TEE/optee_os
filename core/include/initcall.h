/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef __INITCALL_H
#define __INITCALL_H

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

#define early_initcall_begin \
			SCATTERED_ARRAY_BEGIN(early_initcall, struct initcall)
#define early_initcall_end \
			SCATTERED_ARRAY_END(early_initcall, struct initcall)

#define service_initcall_begin \
			SCATTERED_ARRAY_BEGIN(service_initcall, struct initcall)
#define service_initcall_end \
			SCATTERED_ARRAY_END(service_initcall, struct initcall)

#define driver_initcall_begin \
			SCATTERED_ARRAY_BEGIN(driver_initcall, struct initcall)
#define driver_initcall_end \
			SCATTERED_ARRAY_END(driver_initcall, struct initcall)

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
 *  | 1. call_preinitcalls()        | In the nexus, final calls         |
 *  | 2. call_initcalls()           +-----------------------------------+
 *  | 3. call_finalcalls()          | 1. nex_*init*() / boot_final()    |
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

#define early_init(fn)			__define_initcall(early_init, 1, fn)
#define early_init_late(fn)		__define_initcall(early_init, 2, fn)
#define service_init_crypto(fn)		__define_initcall(service_init, 1, fn)
#define service_init(fn)		__define_initcall(service_init, 2, fn)
#define service_init_late(fn)		__define_initcall(service_init, 3, fn)
#define driver_init(fn)			__define_initcall(driver_init, 1, fn)
#define driver_init_late(fn)		__define_initcall(driver_init, 2, fn)
#define release_init_resource(fn)	__define_initcall(driver_init, 3, fn)

/*
 * These nex_* init-calls are provided for drivers and services that reside
 * in the nexus in case of virtualization. The init-calls are performed
 * before exiting to the non-secure world at the end of boot
 * initialization. In case of virtualization the init-calls are based on
 * final calls, while otherwise are the same as the non-nex counterpart.
 */
#ifdef CFG_NS_VIRTUALIZATION
#define nex_early_init(fn)		__define_initcall(final, 1, fn)
#define nex_early_init_late(fn)		__define_initcall(final, 2, fn)
#define nex_service_init(fn)		__define_initcall(final, 3, fn)
#define nex_service_init_late(fn)	__define_initcall(final, 4, fn)
#define nex_driver_init(fn)		__define_initcall(final, 5, fn)
#define nex_driver_init_late(fn)	__define_initcall(final, 6, fn)
#define nex_release_init_resource(fn)	__define_initcall(final, 7, fn)
#else
#define nex_early_init(fn)		early_init(fn)
#define nex_early_init_late(fn)		early_init_late(fn)
#define nex_service_init(fn)		service_init(fn)
#define nex_service_init_late(fn)	service_init_late(fn)
#define nex_driver_init(fn)		driver_init(fn)
#define nex_driver_init_late(fn)	driver_init_late(fn)
#define nex_release_init_resource(fn)	release_init_resource(fn)
#endif

#define boot_final(fn)			__define_initcall(final, 8, fn)

void call_preinitcalls(void);
void call_early_initcalls(void);
void call_service_initcalls(void);
void call_driver_initcalls(void);
void call_finalcalls(void);

#endif
