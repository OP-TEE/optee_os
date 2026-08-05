/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025-2026, NVIDIA CORPORATION
 */

#ifndef TEGRA_UTC_H
#define TEGRA_UTC_H

#include <drivers/serial.h>
#include <types_ext.h>

#ifndef TEGRA_UTC_BASE
#define TEGRA_UTC_BASE			0x0C4E0000
#endif

#define TEGRA_UTC_TX_BASE		(TEGRA_UTC_BASE + 0x30000)
#define TEGRA_UTC_TX_SIZE		0x1000

struct tegra_utc_data {
	struct io_pa_va base;
	size_t base_size;
	struct serial_chip chip;
};

void tegra_utc_init(struct tegra_utc_data *utcd,
		    struct io_pa_va base, size_t size);

#endif
