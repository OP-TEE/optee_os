// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <drivers/serial.h>
#include <kernel/spinlock.h>
#include <riscv.h>
#include <sbi.h>
#include <trace.h>
#include <util.h>

struct sbi_console_data {
	struct serial_chip chip;
};

static struct sbi_console_data console_data __nex_bss;

static void sbi_console_putc(struct serial_chip *chip __unused,
			     int ch)
{
	sbi_console_putchar(ch);
}

static const struct serial_ops sbi_console_ops = {
	.putc = sbi_console_putc,
};

static void sbi_console_init(struct sbi_console_data *pd)
{
	pd->chip.ops = &sbi_console_ops;
}

void console_init(void)
{
	sbi_console_init(&console_data);
	register_serial_console(&console_data.chip);
}
