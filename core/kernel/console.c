// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <compiler.h>
#include <console.h>
#include <drivers/cbmem_console.h>
#include <drivers/semihosting_console.h>
#include <drivers/ffa_console.h>
#include <drivers/serial.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>

static struct serial_chip *serial_console __nex_bss;

/* May be overridden by platform */
__weak void plat_console_init(void)
{
}

void console_init(void)
{
	if (IS_ENABLED(CFG_SEMIHOSTING_CONSOLE))
		semihosting_console_init(CFG_SEMIHOSTING_CONSOLE_FILE);
	else if (IS_ENABLED(CFG_FFA_CONSOLE))
		ffa_console_init();
	else
		plat_console_init();
}

void __weak console_putc(int ch)
{
	if (!serial_console)
		return;

	if (ch == '\n')
		serial_console->ops->putc(serial_console, '\r');
	serial_console->ops->putc(serial_console, ch);
}

void __weak console_flush(void)
{
	if (!serial_console || !serial_console->ops->flush)
		return;

	serial_console->ops->flush(serial_console);
}

void register_serial_console(struct serial_chip *chip)
{
	serial_console = chip;
}

#ifdef CFG_DT
static int find_chosen_node(void *fdt)
{
	int offset = 0;

	if (!fdt)
		return -1;

	offset = fdt_path_offset(fdt, "/secure-chosen");

	if (offset < 0)
		offset = fdt_path_offset(fdt, "/chosen");

	return offset;
}

TEE_Result get_console_node_from_dt(void *fdt, int *offs_out,
				    char **path_out, char **params_out)
{
	const struct fdt_property *prop;
	const char *uart;
	const char *parms = NULL;
	int offs;
	char *stdout_data;
	char *p;
	TEE_Result rc = TEE_ERROR_GENERIC;

	/* Probe console from secure DT and fallback to non-secure DT */
	offs = find_chosen_node(fdt);
	if (offs < 0) {
		DMSG("No console directive from DTB");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	prop = fdt_get_property(fdt, offs, "stdout-path", NULL);
	if (!prop) {
		/*
		 * A secure-chosen or chosen node is present but defined
		 * no stdout-path property: no console expected
		 */
		IMSG("Switching off console");
		register_serial_console(NULL);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	stdout_data = nex_strdup(prop->data);
	if (!stdout_data)
		panic();
	p = strchr(stdout_data, ':');
	if (p) {
		*p = '\0';
		parms = p + 1;
	}

	/* stdout-path may refer to an alias */
	uart = fdt_get_alias(fdt, stdout_data);
	if (!uart) {
		/* Not an alias, assume we have a node path */
		uart = stdout_data;
	}
	offs = fdt_path_offset(fdt, uart);
	if (offs >= 0) {
		if (offs_out)
			*offs_out = offs;
		if (params_out)
			*params_out = parms ? nex_strdup(parms) : NULL;
		if (path_out)
			*path_out = uart ? nex_strdup(uart) : NULL;

		rc = TEE_SUCCESS;
	}

	nex_free(stdout_data);

	return rc;
}

void configure_console_from_dt(void)
{
	const struct dt_driver *dt_drv;
	const struct serial_driver *sdrv;
	struct serial_chip *dev;
	char *uart = NULL;
	char *parms = NULL;
	void *fdt;
	int offs;

	fdt = get_dt();

	if (IS_ENABLED(CFG_CBMEM_CONSOLE) && cbmem_console_init_from_dt(fdt))
		return;

	if (get_console_node_from_dt(fdt, &offs, &uart, &parms))
		return;

	dt_drv = dt_find_compatible_driver(fdt, offs);
	if (!dt_drv || dt_drv->type != DT_DRIVER_UART)
		goto out;

	sdrv = (const struct serial_driver *)dt_drv->driver;
	if (!sdrv)
		goto out;

	dev = sdrv->dev_alloc();
	if (!dev)
		goto out;

	/*
	 * If the console is the same as the early console, dev_init() might
	 * clear pending data. Flush to avoid that.
	 */
	console_flush();
	if (sdrv->dev_init(dev, fdt, offs, parms) < 0) {
		sdrv->dev_free(dev);
		goto out;
	}

	IMSG("Switching console to device: %s", uart);
	register_serial_console(dev);
out:
	nex_free(uart);
	nex_free(parms);
}

#endif /* CFG_DT */
