// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 SiFive, Inc
 */

#include <drivers/sifive_uart.h>
#include <io.h>

/* SiFive UART register defines */
#define UART_REG_TXFIFO         0x0
#define UART_REG_RXFIFO         0x4
#define UART_REG_TXCTRL         0x8
#define UART_REG_RXCTRL         0xC
#define UART_REG_IE             0x10
#define UART_REG_IP             0x14
#define UART_REG_DIV            0x18

/* SiFive UART status register bits */
#define UART_TXFIFO_FULL        0x80000000
#define UART_RXFIFO_EMPTY       0x80000000
#define UART_RXFIFO_DATA        0x000000FF
#define UART_TXCTRL_TXEN        0x1
#define UART_RXCTRL_RXEN        0x1

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct sifive_uart_data *pd =
		container_of(chip, struct sifive_uart_data, chip);

	return io_pa_or_va(&pd->base, SIFIVE_UART_REG_SIZE);
}

static void sifive_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (io_read32(base + UART_REG_TXFIFO) & UART_TXFIFO_FULL) {
		/* Wait until transmit FIFO is not full */
		;
	}
}

static bool sifive_uart_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	return !(io_read32(base + UART_REG_RXFIFO) & UART_RXFIFO_EMPTY);
}

static int sifive_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!sifive_uart_have_rx_data(chip)) {
		/* Wait until data is available in the receive FIFO */
		;
	}
	return io_read32(base + UART_REG_RXFIFO) & UART_RXFIFO_DATA;
}

static void sifive_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	sifive_uart_flush(chip);

	/* Write out character to transmit FIFO */
	io_write32(base + UART_REG_TXFIFO, ch);
}

static const struct serial_ops sifive_uart_ops = {
	.flush = sifive_uart_flush,
	.getchar = sifive_uart_getchar,
	.have_rx_data = sifive_uart_have_rx_data,
	.putc = sifive_uart_putc,
};

void sifive_uart_init(struct sifive_uart_data *pd, paddr_t base,
		      uint32_t uart_clk, uint32_t baud_rate)
{
	uint32_t divisor = 0;

	pd->base.pa = base;
	pd->chip.ops = &sifive_uart_ops;

	/* Configure baudrate */
	if (uart_clk && baud_rate) {
		divisor = (uart_clk + baud_rate - 1) / baud_rate - 1;
		io_write32(base + UART_REG_DIV, divisor);
	}

	/* Disable interrupts */
	io_write32(base + UART_REG_IE, 0);

	/* Enable TX */
	io_write32(base + UART_REG_TXCTRL, UART_TXCTRL_TXEN);

	/* Enable RX */
	io_write32(base + UART_REG_RXCTRL, UART_RXCTRL_RXEN);
}
