// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Timesys Corporation.
 * Copyright (C) 2021 Microchip
 * All rights reserved.
 */

#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <matrix.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <sam_sfr.h>
#include <platform_config.h>
#include <types_ext.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SFR_BASE, CORE_MMU_PGDIR_SIZE);

vaddr_t sam_sfr_base(void)
{
	static void *va;

	if (!cpu_mmu_enabled())
		return SFR_BASE;

	if (!va)
		va = phys_to_virt(SFR_BASE, MEM_AREA_IO_SEC, 1);

	return (vaddr_t)va;
}

void atmel_sfr_set_usb_suspend(bool set)
{
	if (set)
		io_setbits32(sam_sfr_base() + AT91_SFR_OHCIICR,
			     AT91_OHCIICR_USB_SUSPEND);
	else
		io_clrbits32(sam_sfr_base() + AT91_SFR_OHCIICR,
			     AT91_OHCIICR_USB_SUSPEND);
}

static TEE_Result atmel_sfr_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	if (fdt_get_status(fdt, node) == DT_STATUS_OK_SEC)
		matrix_configure_periph_secure(AT91C_ID_SFR);

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_sfr_match_table[] = {
	{ .compatible = "atmel,sama5d2-sfr" },
	{ }
};

DEFINE_DT_DRIVER(atmel_sfr_dt_driver) = {
	.name = "atmel_sfr",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_sfr_match_table,
	.probe = atmel_sfr_probe,
};
