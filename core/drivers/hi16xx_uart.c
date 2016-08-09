/*
 * Copyright (c) 2016, Linaro Limited
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
#include <drivers/hi16xx_uart.h>
#include <io.h>

/* Register offsets */

#define UART_RBR	0x00	/* RX data buffer register */
#define UART_THR	0x00	/* TX data buffer register */
#define UART_DLL	0x00	/* Lower-bit frequency divider register */

#define UART_IEL	0x04	/* Interrupt enable register */
#define UART_DLH	0x04	/* Upper-bit frequency divider register */

#define UART_FCR	0x08	/* FIFO control register */

#define UART_LCR	0x0C	/* Line control register */

#define UART_LSR	0x14	/* Line status register */

#define UART_USR	0x7C	/* Status register */

/*
 * Line control register
 */

/* Data length selection */
#define UART_LCR_DLS5	0x0	/* 5 bits */
#define UART_LCR_DLS6	0x1	/* 6 bits */
#define UART_LCR_DLS7	0x2	/* 7 bits */
#define UART_LCR_DLS8	0x3	/* 8 bits */

/* Enable access to UART_DLL and UART_DLH */
#define UART_LCR_DLAB	0x80

/*
 * FIFO control register
 */

#define UART_FCR_FIFO_EN	0x1	/* Enable FIFO (depth: 32 bytes) */
#define UART_FCR_RX_FIFO_RST	0x2	/* Clear receive FIFO (auto reset) */
#define UART_FCR_TX_FIFO_RST	0x4	/* Clear send FIFO (auto reset) */


/*
 * Status register
 */

#define UART_USR_BUSY_BIT	0	/* 0: idle/non-activated, 1: busy */
#define UART_USR_TFNF_BIT	1	/* Transmit FIFO not full bit */
#define UART_USR_TFE_BIT	2	/* Transmit FIFO empty bit */
#define UART_USR_RFNE_BIT	3	/* Receive FIFO not empty bit */
#define UART_USR_RFF_BIT	4	/* Receive FIFO full bit */

void hi16xx_uart_flush(vaddr_t base)
{
	while (!(read32(base + UART_USR) & UART_USR_TFE_BIT))
		;
}

void hi16xx_uart_init(vaddr_t base, uint32_t uart_clk, uint32_t baud_rate)
{
	uint16_t freq_div = uart_clk / (16 * baud_rate);

	/* Enable (and clear) FIFOs */
	write32(UART_FCR_FIFO_EN, base + UART_FCR);

	/* Enable access to _DLL and _DLH */
	write32(UART_LCR_DLAB, base + UART_LCR);

	/* Calculate and set UART_DLL */
	write32(freq_div & 0xFF, base + UART_DLL);

	/* Calculate and set UART_DLH */
	write32((freq_div >> 8) & 0xFF, base + UART_DLH);

	/* Clear _DLL/_DLH access bit, set data size (8 bits), parity etc. */
	write32(UART_LCR_DLS8, base + UART_LCR);

	/* Disable interrupt mode */
	write32(0, base + UART_IEL);

	hi16xx_uart_flush(base);
}

void hi16xx_uart_putc(int ch, vaddr_t base)
{
	/* Wait until TX FIFO is empty */
	while (!(read32(base + UART_USR) & UART_USR_TFE_BIT))
		;

	/* Put character into TX FIFO */
	write32(ch & 0xFF, base + UART_THR);
}

bool hi16xx_uart_have_rx_data(vaddr_t base)
{
	return (read32(base + UART_USR) & UART_USR_RFNE_BIT);
}

int hi16xx_uart_getchar(vaddr_t base)
{
	while (!hi16xx_uart_have_rx_data(base))
		;
	return read32(base + UART_RBR) & 0xFF;
}

