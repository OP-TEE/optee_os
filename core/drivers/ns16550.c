// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2017, 2020, Linaro Limited
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

#include <drivers/ns16550.h>
#include <keep.h>
#include <util.h>

/* uart register defines */
#define UART_RBR	0x0
#define UART_THR	0x0
#define UART_IER	0x1
#define UART_FCR	0x2
#define UART_LCR	0x3
#define UART_MCR	0x4
#define UART_LSR	0x5
#define UART_MSR	0x6
#define UART_SPR	0x7

/* uart status register bits */
#define UART_LSR_DR	0x01 /* DATA Ready */
#define UART_LSR_THRE	0x20 /* Transmit-hold-register empty */

static vaddr_t chip_to_base_and_data(struct serial_chip *chip,
				     struct ns16550_data **pd)
{
	*pd = container_of(chip, struct ns16550_data, chip);

	return io_pa_or_va(&(*pd)->base, NS16550_UART_REG_SIZE);
}

static void ns16550_flush(struct serial_chip *chip)
{
	struct ns16550_data *pd = NULL;
	vaddr_t base = chip_to_base_and_data(chip, &pd);

	while ((serial_in(base + (UART_LSR << pd->reg_shift), pd->io_width) &
		UART_LSR_THRE) == 0)
		;
}

static void ns16550_putc(struct serial_chip *chip, int ch)
{
	struct ns16550_data *pd = NULL;
	vaddr_t base = chip_to_base_and_data(chip, &pd);

	ns16550_flush(chip);

	/* write out charset to Transmit-hold-register */
	serial_out(base + (UART_THR << pd->reg_shift), pd->io_width, ch);
}

static bool ns16550_have_rx_data(struct serial_chip *chip)
{
	struct ns16550_data *pd = NULL;
	vaddr_t base = chip_to_base_and_data(chip, &pd);

	return serial_in(base + (UART_LSR << pd->reg_shift), pd->io_width) &
	       UART_LSR_DR;
}

static int ns16550_getchar(struct serial_chip *chip)
{
	struct ns16550_data *pd = NULL;
	vaddr_t base = chip_to_base_and_data(chip, &pd);

	while (!ns16550_have_rx_data(chip)) {
		/* Data is not ready, waiting again */
		;
	}

	return serial_in(base + (UART_RBR << pd->reg_shift), pd->io_width) &
	       0xFF;
}

static const struct serial_ops ns16550_ops = {
	.flush = ns16550_flush,
	.putc = ns16550_putc,
	.getchar = ns16550_getchar,
	.have_rx_data = ns16550_have_rx_data,
};
DECLARE_KEEP_PAGER(ns16550_ops);

void ns16550_init(struct ns16550_data *pd, paddr_t base, uint8_t io_width,
		  uint8_t reg_shift)
{
	pd->base.pa = base;
	pd->io_width = io_width;
	pd->reg_shift = reg_shift;
	pd->chip.ops = &ns16550_ops;

	/*
	 * Do nothing, uart driver shared with normal world,
	 * everything for uart driver initialization is done in bootloader.
	 */
}
