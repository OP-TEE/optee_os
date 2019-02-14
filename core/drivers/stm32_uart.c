// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <compiler.h>
#include <console.h>
#include <drivers/serial.h>
#include <drivers/stm32_uart.h>
#include <io.h>
#include <keep.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
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

#define PUTC_TIMEOUT_US			1000
#define FLUSH_TIMEOUT_US		16000

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
	struct stm32_uart_pdata *pd;

	pd = container_of(chip, struct stm32_uart_pdata, chip);

	return io_pa_or_va(&pd->base);
}

static void loc_flush(struct serial_chip *chip)
{
	vaddr_t base = loc_chip_to_base(chip);
	uint64_t timeout = timeout_init_us(FLUSH_TIMEOUT_US);

	while (!(io_read32(base + UART_REG_ISR) & USART_ISR_TXFE))
		if (timeout_elapsed(timeout))
			return;
}

static void loc_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = loc_chip_to_base(chip);
	uint64_t timeout = timeout_init_us(PUTC_TIMEOUT_US);

	while (!(io_read32(base + UART_REG_ISR) & USART_ISR_TXE_TXFNF))
		if (timeout_elapsed(timeout))
			return;

	io_write32(base + UART_REG_TDR, ch);
}

static bool loc_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = loc_chip_to_base(chip);

	return io_read32(base + UART_REG_ISR) & USART_ISR_RXNE_RXFNE;
}

static int loc_getchar(struct serial_chip *chip)
{
	vaddr_t base = loc_chip_to_base(chip);

	while (!loc_have_rx_data(chip))
		;

	return io_read32(base + UART_REG_RDR) & 0xff;
}

static const struct serial_ops stm32_uart_serial_ops = {
	.flush = loc_flush,
	.putc = loc_putc,
	.have_rx_data = loc_have_rx_data,
	.getchar = loc_getchar,

};
KEEP_PAGER(stm32_uart_serial_ops);

void stm32_uart_init(struct stm32_uart_pdata *pd, vaddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &stm32_uart_serial_ops;
}

#ifdef CFG_DT
struct stm32_uart_pdata *stm32_uart_init_from_dt_node(void *fdt, int node)
{
	struct stm32_uart_pdata *pd;
	struct dt_node_info info;

	_fdt_fill_device_info(fdt, &info, node);

	if (info.status == DT_STATUS_DISABLED)
		return NULL;

	if (info.clock < 0)
		panic();

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		panic();

	pd->chip.ops = &stm32_uart_serial_ops;
	pd->base.pa = info.reg;
	pd->secure = (info.status == DT_STATUS_OK_SEC);
	pd->clock = (unsigned int)info.clock;

	assert(cpu_mmu_enabled());
	pd->base.va = (vaddr_t)phys_to_virt(pd->base.pa,
					    pd->secure ? MEM_AREA_IO_SEC :
					    MEM_AREA_IO_NSEC);

	return pd;
}
#endif /*CFG_DT*/
