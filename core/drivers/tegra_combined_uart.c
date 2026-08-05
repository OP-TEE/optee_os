// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2026, NVIDIA CORPORATION
 */

#include <drivers/tegra_combined_uart.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <util.h>

#define TX_TIMEOUT_US		15000

/*
 * Triggers an interrupt. Also indicates that the remote processor
 * is busy when set.
 */
#define MBOX_INTR_TRIGGER	BIT(31)
/*
 * Ensures that prints up to and including this packet are flushed on
 * the physical uart before de-asserting MBOX_INTR_TRIGGER.
 */
#define MBOX_FLUSH		BIT(26)
/*
 * Indicates that we're only sending one byte at a time.
 */
#define MBOX_BYTE_COUNT		BIT(24)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct tegra_combined_uart_data *tcud =
		container_of(chip, struct tegra_combined_uart_data, chip);

	return io_pa_or_va(&tcud->base, tcud->base_size);
}

static void send_msg(vaddr_t base, uint32_t msg)
{
	uint64_t timeout = timeout_init_us(TX_TIMEOUT_US);

	while (io_read32(base) & MBOX_INTR_TRIGGER)
		if (timeout_elapsed(timeout))
			return;

	io_write32(base, msg);
}

static void comb_uart_putc(struct serial_chip *chip, int c)
{
	uint32_t msg;
	vaddr_t base = chip_to_base(chip);

	msg = MBOX_INTR_TRIGGER | MBOX_BYTE_COUNT | (uint8_t)c;
	send_msg(base, msg);
}

static void comb_uart_flush(struct serial_chip *chip)
{
	uint32_t msg = MBOX_INTR_TRIGGER | MBOX_FLUSH;
	vaddr_t base = chip_to_base(chip);

	send_msg(base, msg);
}

static int comb_uart_getc(struct serial_chip *chip __unused)
{
	return -1;
}

static bool comb_uart_have_rx_data(struct serial_chip *chip __unused)
{
	return false;
}

static const struct serial_ops comb_uart_ops = {
	.flush = comb_uart_flush,
	.getchar = comb_uart_getc,
	.have_rx_data = comb_uart_have_rx_data,
	.putc = comb_uart_putc,
};
DECLARE_KEEP_PAGER(comb_uart_ops);

void tegra_combined_uart_init(struct tegra_combined_uart_data *tcud,
			      struct io_pa_va base, size_t size)
{
	if (!tcud)
		return;

	tcud->base = base;
	tcud->base_size = size;
	tcud->chip.ops = &comb_uart_ops;
}

#ifdef CFG_DT

static struct serial_chip *tegra_combined_uart_dev_alloc(void)
{
	struct tegra_combined_uart_data *tcud = nex_calloc(1, sizeof(*tcud));

	if (!tcud)
		return NULL;

	return &tcud->chip;
}

static int tegra_combined_uart_dev_init(struct serial_chip *chip,
					const void *fdt, int offs,
					const char *params)
{
	struct tegra_combined_uart_data *tcud = container_of(chip,
		struct tegra_combined_uart_data, chip);
	struct io_pa_va base = { 0 };
	size_t size = 0;

	if (params && params[0])
		IMSG("tegra_tcu: device parameters ignored (%s)", params);

	if (dt_map_dev(fdt, offs, &base.va, &size, DT_MAP_AUTO) < 0) {
		EMSG("tegra_tcu: failed to map memory");
		return -1;
	}

	if (size < TEGRA_COMBUART_SIZE) {
		EMSG("tegra_tcu: unexpected register size: %zx", size);
		return -1;
	}

	base.pa = virt_to_phys((void *)base.va);
	tegra_combined_uart_init(tcud, base, size);

	return 0;
}

static void tegra_combined_uart_dev_free(struct serial_chip *chip)
{
	struct tegra_combined_uart_data *tcud = container_of(chip,
		struct tegra_combined_uart_data, chip);

	nex_free(tcud);
}

static const struct serial_driver tegra_combined_uart_driver = {
	.dev_alloc = tegra_combined_uart_dev_alloc,
	.dev_init = tegra_combined_uart_dev_init,
	.dev_free = tegra_combined_uart_dev_free,
};

static const struct dt_device_match tegra_combined_uart_match_table[] = {
	{ .compatible = "nvidia,tegra234-tcu" },
	{ 0 }
};

DEFINE_DT_DRIVER(tegra_combined_uart_dt_driver) = {
	.name = "tegra_combined_uart",
	.type = DT_DRIVER_UART,
	.match_table = tegra_combined_uart_match_table,
	.driver = &tegra_combined_uart_driver,
};

#endif /* CFG_DT */
