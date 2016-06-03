/*
 * Copyright (c) 2016, Spreadtrum Communications Inc.
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
#include <io.h>
#include <drivers/sprd_uart.h>

/* Register definitions */
#define UART_TXD		0x0000
#define UART_RXD		0x0004
#define UART_STS1		0x000C /* data number in TX and RX fifo */

/* Register Bit Fields*/
#define STS1_RXF_CNT_MASK	0x00ff  /* Rx FIFO data counter mask */
#define STS1_TXF_CNT_MASK	0xff00 /* Tx FIFO data counter mask */

static uint32_t sprd_uart_read(vaddr_t base, uint32_t reg)
{
	return read32(base + reg);
}

static void sprd_uart_write(vaddr_t base, uint32_t reg, uint32_t value)
{
	write32(value, base + reg);
}

static void sprd_uart_wait_xmit_done(vaddr_t base)
{
	while (sprd_uart_read(base, UART_STS1) & STS1_TXF_CNT_MASK)
		;
}

static void sprd_uart_wait_rx_data(vaddr_t base)
{
	while (!(sprd_uart_read(base, UART_STS1) & STS1_RXF_CNT_MASK))
		;
}

void sprd_uart_flush(vaddr_t base)
{
	sprd_uart_wait_xmit_done(base);
}

void sprd_uart_putc(vaddr_t base, unsigned char ch)
{
	sprd_uart_wait_xmit_done(base);

	sprd_uart_write(base, UART_TXD, (uint32_t)ch);
}

unsigned char sprd_uart_getc(vaddr_t base)
{
	sprd_uart_wait_rx_data(base);

	return sprd_uart_read(base, UART_RXD) & 0xff;
}
