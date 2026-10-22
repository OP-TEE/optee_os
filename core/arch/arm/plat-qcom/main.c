// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/qcom_geni_uart.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <trace.h>

#include "diag_log.h"

/*
 * Register the physical memory area for peripherals etc. Here we are
 * registering the UART console.
 */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, GENI_UART_REG_BASE,
			GENI_UART_REG_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
#ifdef _CFG_ARM_GIC_V3_OR_V4
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE,
			GIC_REDIST_REG_SIZE * CFG_TEE_CORE_NB_CORE);
#else
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif
#ifdef DRAM2_BASE
register_ddr(DRAM2_BASE, DRAM2_SIZE);
#endif

static struct qcom_geni_uart_data console_data;

void plat_trace_ext_puts(const char *str)
{
	qcom_diag_log_puts(str);
}

void plat_trace_init(void)
{
	qcom_diag_log_init();
}

void plat_console_init(void)
{
	if (IS_ENABLED(CFG_QCOM_GENI_UART)) {
		qcom_geni_uart_init(&console_data, GENI_UART_REG_BASE);
		register_serial_console(&console_data.chip);
	}
}

static TEE_Result platform_banner(void)
{
	IMSG("Platform Qualcomm: Flavor %s", TO_STR(PLATFORM_FLAVOR));

	return TEE_SUCCESS;
}

boot_final(platform_banner);

/*
 * Take the GIC register bases from the DT when it describes the interrupt
 * controller, keep the compile-time bases otherwise. The first register
 * window is the distributor, the second one the redistributors (GICv3/v4) or
 * the CPU interface (GICv2).
 */
static void get_gic_bases_from_dt(const char *compatible, paddr_t *gicd_base,
				  paddr_t *gicx_base)
{
	const void *fdt = NULL;
	paddr_t base[2] = { };
	size_t size[2] = { };
	int node = -1;
	int i = 0;

	if (!IS_ENABLED(CFG_DT))
		return;

	fdt = get_dt();
	if (!fdt)
		return;

	node = fdt_node_offset_by_compatible(fdt, -1, compatible);
	if (node < 0) {
		DMSG("GIC: no %s node in DT, using built-in bases", compatible);
		return;
	}

	for (i = 0; i < 2; i++) {
		if (fdt_get_reg_props_by_index(fdt, node, i, &base[i],
					       &size[i]) ||
		    !core_mmu_add_mapping(MEM_AREA_IO_SEC, base[i], size[i])) {
			EMSG("GIC: bad reg %d in DT, using built-in bases", i);
			return;
		}
	}

	DMSG("GIC: bases from DT: 0x%"PRIxPA" 0x%"PRIxPA, base[0], base[1]);
	*gicd_base = base[0];
	*gicx_base = base[1];
}

void boot_primary_init_intc(void)
{
	paddr_t gicd_base = GICD_BASE;

#ifdef _CFG_ARM_GIC_V3_OR_V4
	paddr_t gicr_base = GICR_BASE;

	get_gic_bases_from_dt("arm,gic-v3", &gicd_base, &gicr_base);
	gic_init_v3(0, gicd_base, gicr_base);
#else
	paddr_t gicc_base = GICC_BASE;

	get_gic_bases_from_dt("qcom,msm-qgic2", &gicd_base, &gicc_base);
	gic_init(gicc_base, gicd_base);
#endif
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
