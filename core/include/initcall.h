/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef INITCALL_H
#define INITCALL_H

#include <scattered_array.h>
#include <tee_api_types.h>

typedef TEE_Result (*initcall_t)(void);

#define __define_initcall(level, fn) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(initcall, level, initcall_t) = \
		(fn)

#define initcall_begin	SCATTERED_ARRAY_BEGIN(initcall, initcall_t)
#define initcall_end	SCATTERED_ARRAY_END(initcall, initcall_t)

#define service_init(fn)	__define_initcall(1, fn)
#define service_init_late(fn)	__define_initcall(2, fn)
#define driver_init(fn)		__define_initcall(3, fn)
#define driver_init_late(fn)	__define_initcall(4, fn)


#endif
