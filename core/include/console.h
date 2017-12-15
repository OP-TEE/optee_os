/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef CONSOLE_H
#define CONSOLE_H

#include <compiler.h>

void console_init(void);
void console_putc(int ch);
void console_flush(void);

struct serial_chip;
void register_serial_console(struct serial_chip *chip);

#ifdef CFG_DT
void configure_console_from_dt(unsigned long phys_fdt);
#else
static inline void configure_console_from_dt(unsigned long phys_fdt __unused)
{}
#endif /* !CFG_DT */

#endif /* CONSOLE_H */

