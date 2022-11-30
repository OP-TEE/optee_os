// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, HiSilicon Limited
 */

#include <assert.h>
#include <drivers/lpc_uart.h>
#include <io.h>
#include <keep.h>
#include <mm/core_mmu.h>
#include <util.h>

static paddr_t chip_to_base(struct serial_chip *chip)
{
	struct lpc_uart_data *pd =
		container_of(chip, struct lpc_uart_data, chip);

	return io_pa_or_va(&pd->base, LPC_SIZE);
}

static void lpc_byte_read(paddr_t addr, uint8_t *data)
{
	uint32_t status = 0;
	uint32_t cnt = 0;

	io_write32(LPC_CMD_REG_OFFSET + addr, LPC_SINGLE_READ);

	io_write32(LPC_OP_LEN_REG_OFFSET + addr, 1);
	io_write32(LPC_ADDR_REG_OFFSET + addr, UART_BASE + UART_LSR);

	io_write32(LPC_START_REG_OFFSET + addr, 1);

	status = io_read32(LPC_IRQ_ST_REG_OFFSET + addr);
	while (!(status & LPC_IRQ_ST_ON)) {
		if (cnt > UART_SEND_LOOP_MAX)
			return;
		cnt++;
		status = io_read32(LPC_IRQ_ST_REG_OFFSET + addr);
	}

	io_write32(LPC_IRQ_ST_REG_OFFSET + addr, LPC_IRQ_ST_ON);

	if (io_read32(LPC_OP_STATUS_REG_OFFSET + addr) & LPC_IRQ_ST_ON)
		*data = io_read32(LPC_RDATA_REG_OFFSET + addr);
}

static void lpc_byte_write(paddr_t addr, uint8_t data)
{
	uint32_t status = 0;
	uint32_t cnt = 0;

	io_write32(LPC_CMD_REG_OFFSET + addr, LPC_SINGLE_WRITE);
	io_write32(LPC_OP_LEN_REG_OFFSET + addr, 1);
	io_write32(LPC_WDATA_REG_OFFSET + addr, data);

	io_write32(LPC_ADDR_REG_OFFSET + addr, UART_BASE + UART_THR);
	io_write32(LPC_START_REG_OFFSET + addr, 1);

	status = io_read32(LPC_IRQ_ST_REG_OFFSET + addr);
	while (!(status & LPC_IRQ_ST_ON)) {
		if (cnt > UART_SEND_LOOP_MAX)
			return;
		cnt++;
		status = io_read32(LPC_IRQ_ST_REG_OFFSET + addr);
	}

	io_write32(LPC_IRQ_ST_REG_OFFSET + addr, LPC_IRQ_ST_ON);
}

static void lpc_uart_core_putc(paddr_t base, int ch)
{
	uint8_t var = '\0';
	uint32_t i = 0;

	for (i = 0; i < UART_SEND_LOOP_MAX; i++) {
		lpc_byte_read(base, &var);
		if ((var & LPC_RADTA_LEN) == LPC_RADTA_LEN)
			break;
	}

	lpc_byte_write(base, ch);

	for (i = 0; i < UART_SEND_LOOP_MAX; i++) {
		lpc_byte_read(base, &var);
		if ((var & LPC_RADTA_LEN) == LPC_RADTA_LEN)
			break;
	}
}

static void lpc_uart_putc(struct serial_chip *chip, int ch)
{
	paddr_t base = chip_to_base(chip);

	lpc_uart_core_putc(base, ch);
}

static const struct serial_ops lpc_uart_ops = {
	.putc = lpc_uart_putc,
};
DECLARE_KEEP_PAGER(lpc_uart_ops);

void lpc_uart_init(struct lpc_uart_data *pd, paddr_t base,
		   uint32_t uart_clk __unused, uint32_t baud_rate __unused)
{
	pd->base.pa = base;
	pd->chip.ops = &lpc_uart_ops;
}

