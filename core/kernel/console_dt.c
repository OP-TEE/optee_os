/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <compiler.h>
#include <console.h>
#include <drivers/serial.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/tee_mmu.h>
#include <stdlib.h>
#include <trace.h>

static struct uart_parms {
	vaddr_t base;
	uint32_t clk;
	uint32_t baud_rate;
	const struct dt_driver *drv;
} console;

static struct serial_driver *serial(const struct dt_driver *drv)
{
	return (struct serial_driver *)drv->driver;
}

void console_init(void)
{
	const void *fdt;
	int offset;
	const struct fdt_property *prop;
	char *stdout_data;
	char *parms __maybe_unused = NULL;
	char *p;
	const char *uart;
	const struct dt_driver *drv, *found = NULL;
	int status;
	struct uart_parms newcon;

	fdt = dt_fdt();
	if (!fdt)
		return;
	offset = fdt_path_offset(fdt, "/chosen");
	if (offset < 0)
		return;
	prop = fdt_get_property(fdt, offset, "secure-stdout-path", NULL);
	if (!prop) {
		prop = fdt_get_property(fdt, offset, "stdout-path", NULL);
		if (!prop)
			return;
	}
	stdout_data = strdup(prop->data);
	if (!stdout_data)
		return;

	for (p = stdout_data; *p; p++) {
		if (*p == ':') {
			*p = '\0';
			parms = p + 1;
			break;
		}
	}

	/*
	 * Here, stdout_data is expected to be either a full path to a DT node
	 * (this is the case when stdout-path is a phandle), or the name of an
	 * alias (when stdout-path is a string such as "serial0" or
	 * "serial0:115200n8"). First check if we have an alias.
	 */
	uart = fdt_get_alias(fdt, stdout_data);
	if (!uart) {
		/* Not an alias, assume we have a node path */
		uart = stdout_data;
	}
	offset = fdt_path_offset(fdt, uart);
	if (offset < 0)
		goto out;

	DMSG("DT console: %s, %s", prop->data, uart);

	for_each_dt_driver(drv) {
		status = fdt_node_check_compatible(fdt, offset,
						   drv->compatible);
		if (status == 0) {
			found = drv;
			break;
		}
	}
	if (!found)
		goto out;

	DMSG("Found compatible driver: %s (%s)", found->name,
	     found->compatible);

	newcon.drv = found;
	newcon.base = dt_reg_base_address(offset);
	if (newcon.base == (paddr_t)-1)
		goto out;

	if (parms)
		DMSG("Warning: parameters ignored: %s", parms);

	DMSG("Switching console to %s", uart);
	serial(newcon.drv)->init(newcon.base, 0, 0);
	console = newcon;
out:
	free(stdout_data);
}

void console_putc(int ch)
{
	if (!console.base)
		return earlycon_putc(ch);
	serial(console.drv)->putc(ch, console.base);
}

void console_flush(void)
{
	if (!console.base)
		return earlycon_flush();
	serial(console.drv)->flush(console.base);
}
