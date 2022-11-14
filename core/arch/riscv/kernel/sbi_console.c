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

#ifdef CFG_RISCV_SBI_CONSOLE

struct sbi_console_data {
	struct serial_chip chip;
};

static struct sbi_console_data console_data __nex_bss;
static unsigned int sbi_console_global_lock __nex_bss = SPINLOCK_UNLOCK;

static void sbi_console_lock_global(void)
{
	cpu_spin_lock(&sbi_console_global_lock);
}

static void sbi_console_unlock_global(void)
{
	cpu_spin_unlock(&sbi_console_global_lock);
}

static void sbi_console_flush(struct serial_chip *chip __unused)
{
}

static void sbi_console_putc(struct serial_chip *chip __unused,
			     int ch)
{
	sbi_console_lock_global();
	sbi_console_putchar(ch);
	sbi_console_unlock_global();
}

static const struct serial_ops sbi_console_ops = {
	.flush = sbi_console_flush,
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

#endif /*CFG_RISCV_SBI_CONSOLE*/

