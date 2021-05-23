// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Spreadtrum Communications Inc.
 * Copyright (c) 2017, Linaro Limited
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
#include <drivers/sprd_uart.h>
#include <io.h>
#include <keep.h>
#include <util.h>

/* Register definitions */
#define UART_TXD		0x0000
#define UART_RXD		0x0004
#define UART_STS1		0x000C /* data number in TX and RX fifo */
#define UART_SIZE		0x0010

/* Register Bit Fields*/
#define STS1_RXF_CNT_MASK	0x00ff  /* Rx FIFO data counter mask */
#define STS1_TXF_CNT_MASK	0xff00 /* Tx FIFO data counter mask */

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct sprd_uart_data *pd =
		container_of(chip, struct sprd_uart_data, chip);

	return io_pa_or_va(&pd->base, UART_SIZE);
}

static void sprd_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (io_read32(base + UART_STS1) & STS1_TXF_CNT_MASK)
		;
}

static bool sprd_uart_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	return !!(io_read32(base + UART_STS1) & STS1_RXF_CNT_MASK);
}

static void sprd_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	sprd_uart_flush(chip);
	io_write32(base + UART_TXD, ch);
}

static int sprd_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!sprd_uart_have_rx_data(chip))
		;

	return io_read32(base + UART_RXD) & 0xff;
}

static const struct serial_ops sprd_uart_ops = {
	.flush = sprd_uart_flush,
	.getchar = sprd_uart_getchar,
	.have_rx_data = sprd_uart_have_rx_data,
	.putc = sprd_uart_putc,
};
DECLARE_KEEP_PAGER(sprd_uart_ops);

void sprd_uart_init(struct sprd_uart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &sprd_uart_ops;
}
