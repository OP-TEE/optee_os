/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2026, NVIDIA CORPORATION & AFFILIATES
 */

#ifndef TEGRA_COMBINED_UART_H
#define TEGRA_COMBINED_UART_H

#include <drivers/serial.h>
#include <types_ext.h>

#ifdef CFG_TEGRA_TCU_APE_HSP2
#define TEGRA_COMBUART_BASE	0x0A9F8000
#else
#define TEGRA_COMBUART_BASE	0x0C198000
#endif
#define TEGRA_COMBUART_SIZE	0x1000

struct tegra_combined_uart_data {
	struct io_pa_va base;
	size_t base_size;
	struct serial_chip chip;
};

void tegra_combined_uart_init(struct tegra_combined_uart_data *tcud,
			      struct io_pa_va base, size_t size);

#endif
