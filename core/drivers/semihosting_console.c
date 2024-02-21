// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <compiler.h>
#include <console.h>
#include <drivers/semihosting_console.h>
#include <drivers/serial.h>
#include <kernel/semihosting.h>
#include <util.h>

/*
 * struct semihosting_console_data - Structure for semihosting console driver
 * @chip - General structure for each serial chip
 * @fd - Handle of the file at @file_path when semihosting_console_init() is
 *       called, or -1 if using the semihosting console
 */
struct semihosting_console_data {
	struct serial_chip chip;
	int fd;
};

static struct semihosting_console_data sh_console_data __nex_bss;

static void semihosting_console_putc(struct serial_chip *chip __unused, int ch)
{
	semihosting_sys_writec(ch);
}

static int semihosting_console_getchar(struct serial_chip *chip __unused)
{
	return semihosting_sys_readc();
}

static const struct serial_ops semihosting_console_ops = {
	.putc = semihosting_console_putc,
	.getchar = semihosting_console_getchar,
};
DECLARE_KEEP_PAGER(semihosting_console_ops);

static void semihosting_console_fd_putc(struct serial_chip *chip __unused,
					int ch)
{
	if (sh_console_data.fd >= 0)
		semihosting_write(sh_console_data.fd, &ch, 1);
}

static const struct serial_ops semihosting_console_fd_ops = {
	.putc = semihosting_console_fd_putc,
};
DECLARE_KEEP_PAGER(semihosting_console_fd_ops);

void semihosting_console_init(const char *file_path)
{
	if (file_path) {
		/* Output log to given file on the semihosting host system. */
		sh_console_data.chip.ops = &semihosting_console_fd_ops;
		sh_console_data.fd =
			semihosting_open(file_path, O_RDWR | O_CREAT | O_TRUNC);
	} else {
		/* Output log to semihosting host debug console. */
		sh_console_data.chip.ops = &semihosting_console_ops;
		sh_console_data.fd = -1;
	}

	register_serial_console(&sh_console_data.chip);
}
