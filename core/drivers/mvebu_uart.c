// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Marvell International Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <assert.h>
#include <drivers/mvebu_uart.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <stdlib.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

/* MVEBU UART Registers */
#define UART_RX_REG		0x00
#define UART_TX_REG		0x04
#define UART_CTRL_REG		0x08
#define UART_STATUS_REG		0x0c
#define UART_BAUD_REG		0x10
#define UART_POSSR_REG		0x14
#define UART_SIZE		0x18

/* Line Status Register bits */
#define UARTLSR_TXFIFOFULL	(1 << 11)       /* Tx Fifo Full */
#define UARTLSR_TXFIFOEMPTY	(1 << 13)
#define UARTLSR_TXEMPTY		(1 << 6)
#define UART_RX_READY		(1 << 4)

/* UART Control Register bits */
#define UART_CTRL_RXFIFO_RESET	(1 << 14)
#define UART_CTRL_TXFIFO_RESET	(1 << 15)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct mvebu_uart_data *pd =
		container_of(chip, struct mvebu_uart_data, chip);

	return io_pa_or_va(&pd->base, UART_SIZE);
}

static void mvebu_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	/*
	 * Wait for the transmit FIFO to be empty.
	 * It can happen that Linux initializes the OP-TEE driver with the
	 * console UART disabled; avoid an infinite loop by checking the UART
	 * enabled flag. Checking it in the loop makes the code safe against
	 * asynchronous disable.
	 */
	while (!(io_read32(base + UART_STATUS_REG) & UARTLSR_TXFIFOEMPTY))
		;
}

static bool mvebu_uart_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	return (io_read32(base + UART_STATUS_REG) & UART_RX_READY);
}

static int mvebu_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!mvebu_uart_have_rx_data(chip))
		;
	return io_read32(base + UART_RX_REG) & 0xff;
}

static void mvebu_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	uint32_t tmp;
	/* wait for space in tx FIFO */
	do {
		tmp = io_read32(base + UART_STATUS_REG);
		tmp &= UARTLSR_TXFIFOFULL;
	} while (tmp == UARTLSR_TXFIFOFULL);

	io_write32(base + UART_TX_REG, ch);
}

static const struct serial_ops mvebu_uart_ops = {
	.flush = mvebu_uart_flush,
	.getchar = mvebu_uart_getchar,
	.have_rx_data = mvebu_uart_have_rx_data,
	.putc = mvebu_uart_putc,
};
DECLARE_KEEP_PAGER(mvebu_uart_ops);

void mvebu_uart_init(struct mvebu_uart_data *pd, paddr_t pbase,
		uint32_t uart_clk, uint32_t baud_rate)
{
	vaddr_t base;
	uint32_t dll = 0;

	pd->base.pa = pbase;
	pd->chip.ops = &mvebu_uart_ops;

	base = io_pa_or_va(&pd->base, UART_SIZE);

	dll = (uart_clk / (baud_rate << 4)) & 0x3FF;

	/* init UART  */
	io_clrsetbits32(base + UART_BAUD_REG, 0x3FF, dll);

	/* set UART to default 16x scheme */
	io_write32(base + UART_POSSR_REG, 0);

	/* reset FIFO */
	io_write32(base + UART_CTRL_REG,
		   UART_CTRL_RXFIFO_RESET | UART_CTRL_TXFIFO_RESET);

	/* No Parity, 1 stop */
	io_write32(base + UART_CTRL_REG, 0);

	mvebu_uart_flush(&pd->chip);
}
