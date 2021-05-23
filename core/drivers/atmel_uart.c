// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Timesys Corporation
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
#include <drivers/atmel_uart.h>
#include <io.h>
#include <keep.h>
#include <util.h>

/* Register definitions */
#define ATMEL_UART_CR		0x0000 /* Control Register */
#define ATMEL_UART_MR		0x0004 /* Mode Register */
#define ATMEL_UART_IER		0x0008 /* Interrupt Enable Register */
#define ATMEL_UART_IDR		0x000c /* Interrupt Disable Register */
#define ATMEL_UART_IMR		0x0010 /* Interrupt Mask Register */
#define ATMEL_UART_SR		0x0014 /* Status Register */
	#define	ATMEL_SR_RXRDY		BIT(0)	/* Receiver Ready */
	#define	ATMEL_SR_TXRDY		BIT(1)	/* Transmitter Ready */
	#define	ATMEL_SR_TXEMPTY	BIT(1)	/* Transmitter Ready */
#define ATMEL_UART_RHR		0x0018 /* Receive Holding Register */
#define ATMEL_UART_THR		0x001c /* Transmit Holding Register */
#define ATMEL_UART_BRGR		0x0020 /* Baud Rate Generator Register */
#define ATMEL_UART_CMPR		0x0024 /* Comparison Register */
#define ATMEL_UART_RTOR		0x0028 /* Receiver Time-out Register */
#define ATMEL_UART_WPMR		0x00e4 /* Write Protect Mode Register */
#define ATMEL_UART_SIZE		0x00e8 /* ATMEL_UART_WPMR + sizeof(uint32_t) */

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct atmel_uart_data *pd =
		container_of(chip, struct atmel_uart_data, chip);

	return io_pa_or_va(&pd->base, ATMEL_UART_SIZE);
}

static void atmel_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + ATMEL_UART_SR) & ATMEL_SR_TXEMPTY))
		;
}

static int atmel_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (io_read32(base + ATMEL_UART_SR) & ATMEL_SR_RXRDY)
		;

	return io_read32(base + ATMEL_UART_RHR);
}

static void atmel_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + ATMEL_UART_SR) & ATMEL_SR_TXRDY))
		;

	io_write32(base + ATMEL_UART_THR, ch);
}

static const struct serial_ops atmel_uart_ops = {
	.flush = atmel_uart_flush,
	.getchar = atmel_uart_getchar,
	.putc = atmel_uart_putc,
};

void atmel_uart_init(struct atmel_uart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &atmel_uart_ops;

	/*
	 * Do nothing, debug uart share with normal world,
	 * everything for uart initialization is done in bootloader.
	 */
}
