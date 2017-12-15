/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef INITCALL_H
#define INITCALL_H

#include <tee_api_types.h>

typedef TEE_Result (*initcall_t)(void);

#define __define_initcall(level, fn) \
	static initcall_t __initcall_##fn __attribute__((used)) \
	__attribute__((__section__(".initcall" level))) = fn

#define service_init(fn)	__define_initcall("1", fn)
#define service_init_late(fn)	__define_initcall("2", fn)
#define driver_init(fn)		__define_initcall("3", fn)
#define driver_init_late(fn)	__define_initcall("4", fn)

#endif
