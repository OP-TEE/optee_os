/*
 * Copyright (c) 2015, Linaro Limited
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
#include <platform_config.h>

#include <drivers/serial8250_uart.h>
#include <console.h>
#include <io.h>
#include <assert.h>
#include <compiler.h>

/* uart register defines */
#define UART_RHR	0x0
#define UART_THR	0x0
#define UART_IER	0x4
#define UART_ISR	0x8
#define UART_FCR	0x8
#define UART_LCR	0xc
#define UART_MCR	0x10
#define UART_LSR	0x14
#define UART_MSR	0x18
#define UART_SPR	0x1c

/* uart status register bits */
#define LSR_TEMT	0x40 /* Transmitter empty */
#define LSR_THRE	0x20 /* Transmit-hold-register empty */
#define LSR_EMPTY	(LSR_TEMT | LSR_THRE)
#define LSR_DR		0x01 /* DATA Ready */

void serial8250_uart_init(vaddr_t __unused base,
		uint32_t __unused uart_clk, uint32_t __unused baud_rate)
{
	/*
	 * do nothing, debug uart(uart0) share with normal world,
	 * everything for uart0 is ready now.
	 */
}

void serial8250_uart_flush_tx_fifo(vaddr_t base)
{
	while (1) {
		uint8_t state = read8(base + UART_LSR);

		/* waiting transmit fifo empty */
		if ((state & LSR_EMPTY) == LSR_EMPTY)
			break;
	}
}

bool serial8250_uart_have_rx_data(vaddr_t base)
{
	return (read32(base + UART_LSR) & LSR_DR);
}

void serial8250_uart_putc(int ch, vaddr_t base)
{
	serial8250_uart_flush_tx_fifo(base);

	/* write out charset to transmit fifo */
	write8(ch, base + UART_THR);
}

int serial8250_uart_getchar(vaddr_t base)
{
	while (!serial8250_uart_have_rx_data(base)) {
		/* transmit fifo is empty, waiting again. */
		;
	}
	return read8(base + UART_RHR);
}

