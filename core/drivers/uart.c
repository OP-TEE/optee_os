/*
 * Copyright (c) 2014, Linaro Limited
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
#include <drivers/uart.h>
#include <io.h>

#define UART_DR		0x00 /* data register */
#define UART_RSR_ECR	0x04 /* receive status or error clear */
#define UART_DMAWM	0x08 /* DMA watermark configure */
#define UART_TIMEOUT	0x0C /* Timeout period */
/* reserved space */
#define UART_FR		0x18 /* flag register */
#define UART_LCRH_RX	0x1C /*receive line control */
#define UART_ILPR	0x20 /* IrDA low-poer */
#define UART_IBRD	0x24 /* integer baud register */
#define UART_FBRD	0x28 /* fractional baud register */
#define UART_LCRH_TX	0x2C /* transmit line control */
#define UART_CR		0x30 /* control register */
#define UART_IFLS	0x34 /* interrupt FIFO level select */
#define UART_IMSC	0x38 /* interrupt mask set/clear */
#define UART_RIS	0x3C /* raw interrupt register */
#define UART_MIS	0x40 /* masked interrupt register */
#define UART_ICR	0x44 /* interrupt clear register */
#define UART_DMACR	0x48 /* DMA control register */

/* flag register bits */
#define UART_FR_RTXDIS	(1 << 13)
#define UART_FR_TERI	(1 << 12)
#define UART_FR_DDCD	(1 << 11)
#define UART_FR_DDSR	(1 << 10)
#define UART_FR_DCTS	(1 << 9)
#define UART_FR_RI	(1 << 8)
#define UART_FR_TXFE	(1 << 7)
#define UART_FR_RXFF	(1 << 6)
#define UART_FR_TXFF	(1 << 5)
#define UART_FR_RXFE	(1 << 4)
#define UART_FR_BUSY	(1 << 3)
#define UART_FR_DCD	(1 << 2)
#define UART_FR_DSR	(1 << 1)
#define UART_FR_CTS	(1 << 0)

/* transmit/recieve line register bits */
#define UART_LCRH_SPS		(1 << 7)
#define UART_LCRH_WLEN_8	(3 << 5)
#define UART_LCRH_WLEN_7	(2 << 5)
#define UART_LCRH_WLEN_6	(1 << 5)
#define UART_LCRH_WLEN_5	(0 << 5)
#define UART_LCRH_FEN		(1 << 4)
#define UART_LCRH_STP2		(1 << 3)
#define UART_LCRH_EPS		(1 << 2)
#define UART_LCRH_PEN		(1 << 1)
#define UART_LCRH_BRK		(1 << 0)

/* control register bits */
#define UART_CR_CTSEN		(1 << 15)
#define UART_CR_RTSEN		(1 << 14)
#define UART_CR_OUT2		(1 << 13)
#define UART_CR_OUT1		(1 << 12)
#define UART_CR_RTS		(1 << 11)
#define UART_CR_DTR		(1 << 10)
#define UART_CR_RXE		(1 << 9)
#define UART_CR_TXE		(1 << 8)
#define UART_CR_LPE		(1 << 7)
#define UART_CR_OVSFACT		(1 << 3)
#define UART_CR_UARTEN		(1 << 0)

#define UART_IMSC_RXIM		(1 << 4)

void uart_flush_tx_fifo(vaddr_t base)
{
	while (!(read32(base + UART_FR) & UART_FR_TXFE))
		;
}

void uart_init(vaddr_t base)
{
	write32(0, base + UART_RSR_ECR);

	/* Configure TX to 8 bits, 1 stop bit, no parity, fifo enabled. */
	write32(UART_LCRH_WLEN_8 | UART_LCRH_FEN, base + UART_LCRH_TX);

	write32(UART_IMSC_RXIM, base + UART_IMSC);

	/* Enable UART and TX */
	write32(UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE, base + UART_CR);

	uart_flush_tx_fifo(base);
}

void uart_putc(int ch, vaddr_t base)
{
	/*
	 * Wait until there is space in the FIFO
	 */
	while (read32(base + UART_FR) & UART_FR_TXFF)
		;

	/* Send the character */
	write32(ch, base + UART_DR);
}

bool uart_have_rx_data(vaddr_t base)
{
	return !(read32(base + UART_FR) & UART_FR_RXFE);
}

int uart_getchar(vaddr_t base)
{
	while (!uart_have_rx_data(base))
		;
	return read32(base + UART_DR) & 0xff;
}

