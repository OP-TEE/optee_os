// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Pengutronix
 * All rights reserved.
 * Copyright 2023 NXP
 *
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <config.h>
#include <drivers/tzc380.h>
#include <imx-regs.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <mm/core_memprot.h>
#include <mm/generic_ram_layout.h>

/*
 * TZASC2_BASE is asserted non null when used.
 * This is needed to compile the code for i.MX6UL/L
 * and i.MX8MQ.
 */
#ifndef TZASC2_BASE
#define TZASC2_BASE			0
#else
register_phys_mem(MEM_AREA_IO_SEC, TZASC2_BASE, TZASC_SIZE);
#endif

register_phys_mem(MEM_AREA_IO_SEC, TZASC_BASE, TZASC_SIZE);

/*
 * i.MX6 needs special handling due to the different GPR locations.
 */
#if defined(CFG_MX6)
#if defined(CFG_MX6UL) || defined(CFG_MX6ULL) || defined (CFG_MX6SLL) || defined (CFG_MX6SX)
register_phys_mem(MEM_AREA_IO_SEC, IOMUXC_GPR_BASE, IOMUXC_SIZE);
#else
register_phys_mem(MEM_AREA_IO_SEC, IOMUXC_BASE, IOMUXC_SIZE);
#endif
#elif defined(IOMUXC_GPR_BASE)
register_phys_mem(MEM_AREA_IO_SEC, IOMUXC_GPR_BASE, IOMUXC_SIZE);
#endif

/* Not all platforms support the GPR offsets yet */
#ifndef IOMUXC_GPR9_OFFSET
#define IOMUXC_GPR9_OFFSET		0
#endif

#ifndef IOMUXC_GPR_GPR10_OFFSET
#define IOMUXC_GPR_GPR10_OFFSET		0
#endif

#define IMX6_TZASC2_BYP			BIT(1)
#define IMX6_TZASC1_BYP			BIT(0)

#define IMX8M_LOCK_GPR_TZASC_EN		BIT(16)
#define IMX8M_TZASC_ID_SWAP_BYPASS	BIT(1)
#define IMX8M_TZASC_EN			BIT(1)

static bool imx6_tzasc_is_enabled(void)
{
	uint32_t mask = 0;
	vaddr_t addr = 0;
	paddr_t base = 0;

	assert(IOMUXC_GPR9_OFFSET != 0);

	if (IS_ENABLED(CFG_MX6UL) || IS_ENABLED(CFG_MX6ULL) ||
	    IS_ENABLED(CFG_MX6SLL) || IS_ENABLED(CFG_MX6SX))
		base = IOMUXC_GPR_BASE;
	else
		base = IOMUXC_BASE;

	addr = core_mmu_get_va(base, MEM_AREA_IO_SEC, IOMUXC_SIZE);
	if (!addr) {
		EMSG("Failed to get GPR");
		return false;
	}

	mask = IMX6_TZASC1_BYP;
	if (IS_ENABLED(CFG_MX6Q) || IS_ENABLED(CFG_MX6D) ||
	    IS_ENABLED(CFG_MX6DL) || IS_ENABLED(CFG_MX6QP))
		mask |= IMX6_TZASC2_BYP;

	return (io_read32(addr + IOMUXC_GPR9_OFFSET) & mask) == mask;
}

static bool imx8m_tzasc_is_enabled(void)
{
	uint32_t mask = 0;
	vaddr_t addr = 0;

	assert(IOMUXC_GPR_GPR10_OFFSET != 0);

	addr = core_mmu_get_va(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC, IOMUXC_SIZE);
	if (!addr) {
		EMSG("Failed to get GPR");
		return false;
	}

	mask = IMX8M_LOCK_GPR_TZASC_EN | IMX8M_TZASC_ID_SWAP_BYPASS |
	       IMX8M_TZASC_EN;

	return (io_read32(addr + IOMUXC_GPR_GPR10_OFFSET) & mask) == mask;
}

static bool imx_tzasc_is_enabled(void)
{

	if (!IS_ENABLED(CFG_TZASC_CHECK_ENABLED)) {
		IMSG("CFG_TZASC_CHECK_ENABLED disabled, please enable");
		return true;
	}

	if (IS_ENABLED(CFG_MX6))
		return imx6_tzasc_is_enabled();
	else if (IS_ENABLED(CFG_MX8M))
		return imx8m_tzasc_is_enabled();

	IMSG("Checking TZASC enable is not supported yet for this platform");
	return false;
}

static int imx_tzc_auto_configure(vaddr_t addr, vaddr_t rsize, uint32_t attr,
				  uint8_t region)
{
	vaddr_t addr_imx = 0;

	/*
	 * On 8mscale platforms, the TZASC controller for the DRAM protection,
	 * has the memory regions starting at address 0x0 instead of the DRAM
	 * base address (0x40000000)
	 */
	if (IS_ENABLED(CFG_MX8M))
		addr_imx = addr - CFG_DRAM_BASE;
	else
		addr_imx = addr;

	return tzc_auto_configure(addr_imx, rsize, attr, region);
}

static TEE_Result imx_configure_tzasc(void)
{
	vaddr_t addr[2] = {0};
	int end = 1;
	int i = 0;

	if (!imx_tzasc_is_enabled())
		panic("TZC380 must be enabled before starting OP-TEE");

	addr[0] = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC, 1);

	if (IS_ENABLED(CFG_MX6Q) || IS_ENABLED(CFG_MX6D) ||
	    IS_ENABLED(CFG_MX6DL) || IS_ENABLED(CFG_MX6QP)) {
		assert(TZASC2_BASE != 0);
		addr[1] = core_mmu_get_va(TZASC2_BASE, MEM_AREA_IO_SEC, 1);
		end = 2;
	}

	for (i = 0; i < end; i++) {
		uint8_t region = 1;

		tzc_init(addr[i]);

		/*
		 * TZC380 is not memory alias aware so an attacker could read
		 * the OP-TEE core memory if the system does support memory
		 * aliasing.
		 *
		 * To fix this region0 needs to be configured as secure access
		 * only (0xc). This is the default if not changed by the
		 * previous running firmware. Region0 covers the complete
		 * platform AXI address space.
		 */
		if (IS_ENABLED(CFG_TZASC_REGION0_SECURE) &&
		    tzc_verify_region0_secure() != TEE_SUCCESS)
			panic("region0 is not secure configured, non-secure memory alias access possible!");

		region = imx_tzc_auto_configure(CFG_DRAM_BASE, CFG_DDR_SIZE,
						TZC_ATTR_SP_NS_RW, region);
		region = imx_tzc_auto_configure(CFG_TZDRAM_START,
						CFG_TZDRAM_SIZE,
						TZC_ATTR_SP_S_RW, region);
		region = imx_tzc_auto_configure(CFG_SHMEM_START, CFG_SHMEM_SIZE,
						TZC_ATTR_SP_ALL, region);

		if (tzc_regions_lockdown() != TEE_SUCCESS)
			panic("Region lockdown failed!");

		tzc_dump_state();
	}
	return TEE_SUCCESS;
}

static TEE_Result
pm_enter_resume(enum pm_op op, uint32_t pm_hint __unused,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_RESUME)
		return imx_configure_tzasc();

	return TEE_SUCCESS;
}

static TEE_Result tzasc_init(void)
{
	register_pm_driver_cb(pm_enter_resume, NULL, "imx-tzasc");

	return imx_configure_tzasc();
}
driver_init(tzasc_init);
