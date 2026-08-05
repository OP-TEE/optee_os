// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2026, NVIDIA CORPORATION
 */

#include <console.h>
#include <drivers/hfic.h>
#include <kernel/boot.h>

#ifdef CFG_TEGRA_TCU
#include <drivers/tegra_combined_uart.h>
#endif

#ifdef CFG_TEGRA_UTC
#include <drivers/tegra_utc.h>
#endif

#ifdef CFG_TEGRA_TCU
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TEGRA_COMBUART_BASE,
			TEGRA_COMBUART_SIZE);
static struct tegra_combined_uart_data tcud;
#endif

#ifdef CFG_TEGRA_UTC
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TEGRA_UTC_TX_BASE, TEGRA_UTC_TX_SIZE);
static struct tegra_utc_data utcd;
#endif

void plat_console_init(void)
{
#ifdef CFG_TEGRA_TCU
	struct io_pa_va base = { .pa = TEGRA_COMBUART_BASE };
#endif

#ifdef CFG_TEGRA_UTC
	struct io_pa_va utc_base = { .pa = TEGRA_UTC_TX_BASE };
#endif

#ifdef CFG_TEGRA_TCU
	tegra_combined_uart_init(&tcud, base, TEGRA_COMBUART_SIZE);
	register_serial_console(&tcud.chip);
#endif

#ifdef CFG_TEGRA_UTC
	tegra_utc_init(&utcd, utc_base, TEGRA_UTC_TX_SIZE);
	register_serial_console(&utcd.chip);
#endif
}

#ifdef CFG_CORE_HAFNIUM_INTC
void boot_primary_init_intc(void)
{
	hfic_init();
}
#endif
