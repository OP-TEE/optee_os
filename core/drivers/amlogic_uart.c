// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Carlo Caione <ccaione@baylibre.com>
 */

#include <assert.h>
#include <drivers/amlogic_uart.h>
#include <io.h>
#include <keep.h>
#include <util.h>

/* Registers */
#define AML_UART_WFIFO		0x0000
#define AML_UART_RFIFO		0x0004
#define AML_UART_CONTROL	0x0008
#define AML_UART_STATUS		0x000C
#define AML_UART_MISC		0x0010
#define AML_UART_SIZE		0x0014

/* AML_UART_STATUS bits */
#define AML_UART_RX_EMPTY	BIT(20)
#define AML_UART_TX_FULL	BIT(21)
#define AML_UART_TX_EMPTY	BIT(22)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct amlogic_uart_data *pd =
		container_of(chip, struct amlogic_uart_data, chip);

	return io_pa_or_va(&pd->base, AML_UART_SIZE);
}

static void amlogic_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + AML_UART_STATUS) & AML_UART_TX_EMPTY))
		;
}

static int amlogic_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	if (io_read32(base + AML_UART_STATUS) & AML_UART_RX_EMPTY)
		return -1;

	return io_read32(base + AML_UART_RFIFO) & 0xff;
}

static void amlogic_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	while (io_read32(base + AML_UART_STATUS) & AML_UART_TX_FULL)
		;

	io_write32(base + AML_UART_WFIFO, ch);
}

static const struct serial_ops amlogic_uart_ops = {
	.flush = amlogic_uart_flush,
	.getchar = amlogic_uart_getchar,
	.putc = amlogic_uart_putc,
};

void amlogic_uart_init(struct amlogic_uart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &amlogic_uart_ops;

	/*
	 * Do nothing, debug uart (AO) shared with normal world, everything for
	 * uart initialization is done in bootloader.
	 */
}
