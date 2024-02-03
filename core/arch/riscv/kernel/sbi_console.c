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
static struct serial_ops sbi_console_ops __nex_bss;

static void sbi_console_putc_legacy(struct serial_chip *chip __unused, int ch)
{
	sbi_console_putchar(ch);
}

static void sbi_console_putc(struct serial_chip *chip __unused, int ch)
{
	sbi_dbcn_write_byte(ch);
}

static void sbi_console_init(struct sbi_console_data *pd)
{
	if (sbi_probe_extension(SBI_EXT_DBCN))
		sbi_console_ops.putc = sbi_console_putc;
	else
		sbi_console_ops.putc = sbi_console_putc_legacy;

	pd->chip.ops = &sbi_console_ops;
}

void plat_console_init(void)
{
	sbi_console_init(&console_data);
	register_serial_console(&console_data.chip);
}
