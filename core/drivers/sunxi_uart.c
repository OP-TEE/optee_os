/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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

#include <drivers/sunxi_uart.h>
#include <io.h>
#include <assert.h>
#include <compiler.h>

/* uart register defines */
#define UART_REG_RBR 	(0x00)
#define UART_REG_THR 	(0x00)
#define UART_REG_DLL 	(0x00)
#define UART_REG_DLH 	(0x04)
#define UART_REG_IER 	(0x04)
#define UART_REG_IIR 	(0x08)
#define UART_REG_FCR 	(0x08)
#define UART_REG_LCR 	(0x0c)
#define UART_REG_MCR 	(0x10)
#define UART_REG_LSR 	(0x14)
#define UART_REG_MSR 	(0x18)
#define UART_REG_SCH 	(0x1c)
#define UART_REG_USR 	(0x7c)
#define UART_REG_TFL 	(0x80)
#define UART_REG_RFL 	(0x84)
#define UART_REG_HALT	(0xa4)

/* uart status register bits */
#define UART_REG_USR_BUSY (0x1 << 0x0)
#define UART_REG_USR_TFNF (0x1 << 0x1)
#define UART_REG_USR_TFE  (0x1 << 0x2)
#define UART_REG_USR_RFNE (0x1 << 0x3)
#define UART_REG_USR_RFF  (0x1 << 0x4)

void sunxi_uart_init(vaddr_t __unused base)
{
	/* do nothing, debug uart(uart0) share with normal world,
	 * everything for uart0 is ready now.
	 */
}

void sunxi_uart_flush(vaddr_t base)
{
	while (read32(base + UART_REG_TFL)) {
		/* waiting transmit fifo empty */
		;
	}
}

bool sunxi_uart_have_rx_data(vaddr_t base)
{
	return read32(base + UART_REG_RFL);
}

void sunxi_uart_putc(int ch, vaddr_t base)
{
	while (!(read32(base + UART_REG_USR) & UART_REG_USR_TFNF)) {
		/* transmit fifo is full, waiting again. */
		;
	}

	/* write out charset to transmit fifo */
	write8(ch, base + UART_REG_THR);
}

int sunxi_uart_getchar(vaddr_t base)
{
	while (!sunxi_uart_have_rx_data(base)) {
		/* transmit fifo is empty, waiting again. */
		;
	}
	return read32(base + UART_REG_RBR) & 0xff;
}

