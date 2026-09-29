// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025-2026, NVIDIA CORPORATION & AFFILIATES
 */

#include <drivers/tegra_utc.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <util.h>

#define TEGRA_UTC_TX_CLIENT_ENABLE(base)	((base) + 0x0000)
#define TEGRA_UTC_TX_CLIENT_COMMAND(base)	((base) + 0x000c)
#define TEGRA_UTC_TX_CLIENT_DATA(base)		((base) + 0x0020)
#define TEGRA_UTC_TX_CLIENT_FIFO_STATUS(base)	((base) + 0x0100)

#define COMMAND_FLUSH				BIT(4)

#define TX_STATUS_FULL				BIT(1)
#define TX_TIMEOUT_US				1000

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct tegra_utc_data *utcd =
		container_of(chip, struct tegra_utc_data, chip);

	return io_pa_or_va(&utcd->base, utcd->base_size);
}

static int32_t tegra_utc_wait_for_ready(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);
	uint64_t timeout = timeout_init_us(TX_TIMEOUT_US);

	while (io_read32(TEGRA_UTC_TX_CLIENT_FIFO_STATUS(base)) &
	       TX_STATUS_FULL)
		if (timeout_elapsed(timeout))
			return -1;

	return 0;
}

static void tegra_utc_putc(struct serial_chip *chip, int c)
{
	vaddr_t base = chip_to_base(chip);
	int32_t err = tegra_utc_wait_for_ready(chip);

	if (err == 0)
		io_write32(TEGRA_UTC_TX_CLIENT_DATA(base), c);
}

static void tegra_utc_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	io_write32(TEGRA_UTC_TX_CLIENT_COMMAND(base), COMMAND_FLUSH);
}

static const struct serial_ops tegra_utc_ops = {
	.flush = tegra_utc_flush,
	.putc = tegra_utc_putc,
};
DECLARE_KEEP_PAGER(tegra_utc_ops);

void tegra_utc_init(struct tegra_utc_data *utcd,
		    struct io_pa_va base, size_t size)
{
	if (!utcd)
		return;

	utcd->base = base;
	utcd->base_size = size;
	utcd->chip.ops = &tegra_utc_ops;
}

#ifdef CFG_DT

static struct serial_chip *tegra_utc_dev_alloc(void)
{
	struct tegra_utc_data *utcd = nex_calloc(1, sizeof(*utcd));

	if (!utcd)
		return NULL;

	return &utcd->chip;
}

static int tegra_utc_dev_init(struct serial_chip *chip,
			      const void *fdt, int offs,
			      const char *params)
{
	struct tegra_utc_data *utcd = container_of(chip,
		struct tegra_utc_data, chip);
	struct io_pa_va base = { 0 };
	size_t size;

	if (params && params[0])
		IMSG("tegra_utc: device parameters ignored (%s)", params);

	if (dt_map_dev(fdt, offs, &base.va, &size, DT_MAP_AUTO) < 0) {
		EMSG("tegra_utc: failed to map memory");
		return -1;
	}

	if (size < TEGRA_UTC_TX_SIZE) {
		EMSG("tegra_utc: unexpected register size: %zx", size);
		return -1;
	}

	base.pa = virt_to_phys((void *)base.va);
	tegra_utc_init(utcd, base, size);

	return 0;
}

static void tegra_utc_dev_free(struct serial_chip *chip)
{
	struct tegra_utc_data *utcd = container_of(chip,
		struct tegra_utc_data, chip);

	nex_free(utcd);
}

static const struct serial_driver tegra_utc_driver = {
	.dev_alloc = tegra_utc_dev_alloc,
	.dev_init = tegra_utc_dev_init,
	.dev_free = tegra_utc_dev_free,
};

static const struct dt_device_match tegra_utc_match_table[] = {
	{ .compatible = "nvidia,tegra264-utc" },
	{ 0 }
};

DEFINE_DT_DRIVER(tegra_utc_dt_driver) = {
	.name = "tegra-utc",
	.type = DT_DRIVER_UART,
	.match_table = tegra_utc_match_table,
	.driver = &tegra_utc_driver,
};

#endif /* CFG_DT */
