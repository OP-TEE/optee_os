// SPDX-License-Identifier: BSD-2-Clause
/*
 * Qualcomm GENI serial engine UART driver
 *
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom_geni_uart.h>
#include <io.h>

#define GENI_STATUS_REG			0x40
#define GENI_STATUS_REG_CMD_ACTIVE	BIT(0)
#define GENI_TX_FIFO_REG		0x700
#define GENI_TX_TRANS_LEN_REG		0x270
#define GENI_M_CMD0_REG			0x600

#define GENI_M_CMD_TX			0x8000000
#define GENI_TIMEOUT_US			1000000

static void qcom_geni_uart_putc(struct serial_chip *chip, int ch)
{
	struct qcom_geni_uart_data *pd =
		container_of(chip, struct qcom_geni_uart_data, chip);
	vaddr_t base = io_pa_or_va(&pd->base, GENI_UART_REG_SIZE);
	uint64_t timer = timeout_init_us(GENI_TIMEOUT_US);

	while (io_read32(base + GENI_STATUS_REG) & GENI_STATUS_REG_CMD_ACTIVE)
		if (timeout_elapsed(timer))
			return;

	io_write32(base + GENI_TX_TRANS_LEN_REG, 1);
	io_write32(base + GENI_M_CMD0_REG, GENI_M_CMD_TX);
	io_write32(base + GENI_TX_FIFO_REG, ch);
}

static const struct serial_ops qcom_geni_uart_ops = {
	.putc = qcom_geni_uart_putc,
};
DECLARE_KEEP_PAGER(qcom_geni_uart_ops);

void qcom_geni_uart_init(struct qcom_geni_uart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &qcom_geni_uart_ops;

	/*
	 * Do nothing, debug uart is shared with normal world, everything
	 * for debug uart initialization is done in the bootloader.
	 */
}
