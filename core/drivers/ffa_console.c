// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024-2025, NVIDIA CORPORATION
 */

#include <compiler.h>
#include <console.h>
#include <drivers/ffa_console.h>
#include <drivers/serial.h>
#include <kernel/dt_driver.h>
#include <kernel/thread_arch.h>

#define FFA_CONSOLE_LOG_32		(0x8400008A)

static void ffa_console_putc(struct serial_chip *chip __unused, int ch)
{
	thread_hvc(FFA_CONSOLE_LOG_32, 1, ch, 0);
}

static const struct serial_ops ffa_console_ops = {
	.putc = ffa_console_putc,
};
DECLARE_KEEP_PAGER(ffa_console_ops);

static struct serial_chip ffa_console = {
	.ops = &ffa_console_ops
};

void ffa_console_init(void)
{
	register_serial_console(&ffa_console);
}

#ifdef CFG_DT

static struct serial_chip *ffa_console_dev_alloc(void)
{
	return &ffa_console;
}

static int ffa_console_dev_init(struct serial_chip *chip __unused,
				const void *fdt __unused, int offs __unused,
				const char *params __unused)
{
	return 0;
}

static void ffa_console_dev_free(struct serial_chip *chip __unused)
{
}

static const struct serial_driver ffa_console_driver = {
	.dev_alloc = ffa_console_dev_alloc,
	.dev_init = ffa_console_dev_init,
	.dev_free = ffa_console_dev_free,
};

static const struct dt_device_match ffa_console_match_table[] = {
	{ .compatible = "arm,ffa-console" },
	{ }
};

DEFINE_DT_DRIVER(ffa_console_dt_driver) = {
	.name = "ffa-console",
	.type = DT_DRIVER_UART,
	.match_table = ffa_console_match_table,
	.driver = &ffa_console_driver,
};

#endif /* CFG_DT */
