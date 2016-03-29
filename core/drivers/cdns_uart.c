/*
 * Copyright (c) 2016, Xilinx Inc.
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
#include <compiler.h>
#include <drivers/cdns_uart.h>
#include <io.h>
#include <util.h>

#define CDNS_UART_CONTROL		0
#define CDNS_UART_MODE			4
#define CDNS_UART_IEN			8
#define CDNS_UART_IRQ_STATUS		0x14
#define CDNS_UART_CHANNEL_STATUS	0x2c
#define CDNS_UART_FIFO			0x30

#define CDNS_UART_CONTROL_RXRES		BIT(0)
#define CDNS_UART_CONTROL_TXRES		BIT(1)
#define CDNS_UART_CONTROL_RXEN		BIT(2)
#define CDNS_UART_CONTROL_TXEN		BIT(4)

#define CDNS_UART_MODE_8BIT		(0 << 1)
#define CDNS_UART_MODE_PARITY_NONE	(0x4 << 3)
#define CDNS_UART_MODE_1STP		(0 << 6)

#define CDNS_UART_CHANNEL_STATUS_TFUL	BIT(4)
#define CDNS_UART_CHANNEL_STATUS_TEMPTY	BIT(3)
#define CDNS_UART_CHANNEL_STATUS_REMPTY	BIT(1)

#define CDNS_UART_IRQ_RXTRIG		BIT(0)
#define CDNS_UART_IRQ_RXTOUT		BIT(8)

void cdns_uart_flush(vaddr_t base)
{
	while (!(read32(base + CDNS_UART_CHANNEL_STATUS) &
				CDNS_UART_CHANNEL_STATUS_TEMPTY))
		;
}

/*
 * we rely on the bootloader having set up the HW correctly, we just enable
 * transmitter/receiver here, just in case.
 */
void cdns_uart_init(vaddr_t base, uint32_t uart_clk, uint32_t baud_rate)
{
	if (!base || !uart_clk || !baud_rate)
		return;

	/* Enable UART and RX/TX */
	write32(CDNS_UART_CONTROL_RXEN | CDNS_UART_CONTROL_TXEN,
		base + CDNS_UART_CONTROL);

	cdns_uart_flush(base);
}

void cdns_uart_putc(int ch, vaddr_t base)
{
	/* Wait until there is space in the FIFO */
	while (read32(base + CDNS_UART_CHANNEL_STATUS) &
			CDNS_UART_CHANNEL_STATUS_TFUL)
		;

	/* Send the character */
	write32(ch, base + CDNS_UART_FIFO);
}

bool cdns_uart_have_rx_data(vaddr_t base)
{
	return !(read32(base + CDNS_UART_CHANNEL_STATUS) &
			CDNS_UART_CHANNEL_STATUS_REMPTY);
}

int cdns_uart_getchar(vaddr_t base)
{
	while (!cdns_uart_have_rx_data(base))
		;
	return read32(base + CDNS_UART_FIFO) & 0xff;
}
