/*
 *  Copyright (c) 2022 Nuvoton Technology Corp.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
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
	if (res > 0)
		boffs += res;

	if (boffs >= (sizeof(buf) - 1))
		boffs = sizeof(buf) - 2;

	buf[boffs] = '\n';
	while (boffs && buf[boffs] == '\n')
		boffs--;
	boffs++;
	buf[boffs + 1] = '\0';

	trace_ext_puts(buf);
}

