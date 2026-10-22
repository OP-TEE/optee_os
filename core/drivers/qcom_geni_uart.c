// SPDX-License-Identifier: BSD-2-Clause
/*
 * Qualcomm GENI serial engine UART driver
 *
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom_geni_uart.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <trace.h>

#define GENI_STATUS_REG			0x40
#define GENI_STATUS_REG_CMD_ACTIVE	BIT(0)
#define GENI_TX_FIFO_REG		0x700
#define GENI_TX_TRANS_LEN_REG		0x270
#define GENI_M_CMD0_REG			0x600

#define GENI_M_CMD_TX			0x8000000
#define GENI_TIMEOUT_US			CFG_QCOM_GENI_UART_RDY_WAIT_USEC

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

#ifdef CFG_DT

static struct serial_chip *qcom_geni_uart_dev_alloc(void)
{
	struct qcom_geni_uart_data *pd = nex_calloc(1, sizeof(*pd));

	if (!pd)
		return NULL;
	return &pd->chip;
}

static int qcom_geni_uart_dev_init(struct serial_chip *chip, const void *fdt,
				   int offs, const char *params)
{
	struct qcom_geni_uart_data *pd =
		container_of(chip, struct qcom_geni_uart_data, chip);
	vaddr_t vbase = 0;
	size_t size = 0;

	if (params && params[0])
		IMSG("qcom_geni_uart: device parameters ignored (%s)", params);

	/* Enabled for both worlds, the UART is shared with the normal world */
	if (dt_map_dev(fdt, offs, &vbase, &size, DT_MAP_AUTO) < 0)
		return -1;

	if (size < GENI_UART_REG_SIZE) {
		EMSG("qcom_geni_uart: unexpected register size: %zx", size);
		return -1;
	}

	qcom_geni_uart_init(pd, virt_to_phys((void *)vbase));

	return 0;
}

static void qcom_geni_uart_dev_free(struct serial_chip *chip)
{
	struct qcom_geni_uart_data *pd =
		container_of(chip, struct qcom_geni_uart_data, chip);

	nex_free(pd);
}

static const struct serial_driver qcom_geni_uart_driver = {
	.dev_alloc = qcom_geni_uart_dev_alloc,
	.dev_init = qcom_geni_uart_dev_init,
	.dev_free = qcom_geni_uart_dev_free,
};

static const struct dt_device_match qcom_geni_uart_match_table[] = {
	{ .compatible = "qcom,geni-debug-uart" },
	{ 0 }
};

DEFINE_DT_DRIVER(qcom_geni_uart_dt_driver) = {
	.name = "qcom_geni_uart",
	.type = DT_DRIVER_UART,
	.match_table = qcom_geni_uart_match_table,
	.driver = &qcom_geni_uart_driver,
};

#endif /* CFG_DT */
