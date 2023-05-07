/*
 * Copyright (c) 2022-2023, ARM Limited and Contributors. All rights reserved.
 *
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NPCMX845_TRACE_H_
#define __NPCMX845_TRACE_H_

#include <trace.h>

void trace_ext_printf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void __attribute__((format(printf, 1, 0))) trace_ext_vprintf(const char *fmt, va_list ap);

#define trace_ext_printf_helper(...) trace_ext_printf(__VA_ARGS__)

#define TMSG(...)   trace_ext_printf(__VA_ARGS__)

#endif /* __NPCMX845_TRACE_H_ */
