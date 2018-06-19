// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <compiler.h>
#include <drivers/serial.h>
#include <drivers/stm32_uart.h>
#include <io.h>
#include <keep.h>
#include <util.h>

#define UART_REG_CR1			0x00	/* Control register 1 */
#define UART_REG_CR2			0x04	/* Control register 2 */
#define UART_REG_CR3			0x08	/* Control register 3 */
#define UART_REG_BRR			0x0c	/* Baud rate register */
#define UART_REG_RQR			0x18	/* Request register */
#define UART_REG_ISR			0x1c	/* Interrupt & status reg. */
#define UART_REG_ICR			0x20	/* Interrupt flag clear reg. */
#define UART_REG_RDR			0x24	/* Receive data register */
#define UART_REG_TDR			0x28	/* Transmit data register */
#define UART_REG_PRESC			0x2c	/* Prescaler register */

/*
 * Uart Interrupt & status register bits
 *
 * Bit 5 RXNE: Read data register not empty/RXFIFO not empty
 * Bit 6 TC: Transmission complete
 * Bit 7 TXE/TXFNF: Transmit data register empty/TXFIFO not full
 * Bit 27 TXFE: TXFIFO threshold reached
 */
#define USART_ISR_RXNE_RXFNE		BIT(5)
#define USART_ISR_TC			BIT(6)
#define USART_ISR_TXE_TXFNF		BIT(7)
#define USART_ISR_TXFE			BIT(27)

static vaddr_t loc_chip_to_base(struct serial_chip *chip)
{
	struct console_pdata *pd =
		container_of(chip, struct console_pdata, chip);

	return io_pa_or_va(&pd->base);
}

static void loc_flush(struct serial_chip *chip)
{
	vaddr_t base = loc_chip_to_base(chip);

	while (!(read32(base + UART_REG_ISR) & USART_ISR_TXFE))
		;
}

static void loc_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = loc_chip_to_base(chip);

	while (!(read32(base + UART_REG_ISR) & USART_ISR_TXE_TXFNF))
		;

	write32(ch, base + UART_REG_TDR);
}

static bool loc_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = loc_chip_to_base(chip);

	return read32(base + UART_REG_ISR) & USART_ISR_RXNE_RXFNE;
}

static int loc_getchar(struct serial_chip *chip)
{
	vaddr_t base = loc_chip_to_base(chip);

	while (!loc_have_rx_data(chip))
		;

	return read32(base + UART_REG_RDR) & 0xff;
}

static const struct serial_ops serial_ops = {
	.flush = loc_flush,
	.putc = loc_putc,
	.have_rx_data = loc_have_rx_data,
	.getchar = loc_getchar,

};
KEEP_PAGER(serial_ops);

void stm32_uart_init(struct console_pdata *pd, vaddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &serial_ops;
}
