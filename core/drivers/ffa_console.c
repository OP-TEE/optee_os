// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, NVIDIA CORPORATION
 */

#include <compiler.h>
#include <console.h>
#include <drivers/ffa_console.h>
#include <drivers/serial.h>
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
