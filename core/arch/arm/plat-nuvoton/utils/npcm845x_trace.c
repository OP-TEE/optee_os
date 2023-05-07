/*
 * Copyright (c) 2022-2023, ARM Limited and Contributors. All rights reserved.
 *
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(__KERNEL__)
#include <platform_config.h>
#endif

#include <utils/npcm845x_trace.h>
#include <printk.h>
#include <stdarg.h>
#include <string.h>
#include <util.h>
#include <types_ext.h>

void trace_ext_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	trace_ext_vprintf(fmt, ap);
	va_end(ap);
}

void trace_ext_vprintf(const char *fmt, va_list ap)
{
	char buf[MAX_PRINT_SIZE];
	size_t boffs = 0;
	int res;

	res = vsnprintk(buf, sizeof(buf), fmt, ap);

	if (res > 0) {
		boffs += res;
	}

	if (boffs >= (sizeof(buf) - 1)) {
		boffs = sizeof(buf) - 2;
	}

	buf[boffs] = '\n';

	while (boffs && buf[boffs] == '\n') {
		boffs--;
	}

	boffs++;
	buf[boffs + 1] = '\0';

	trace_ext_puts(buf);
}

