// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#include <common.h>
#include <console.h>
#include <cru.h>
#include <grf.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

struct dram_data {
	uint32_t cru_mode_con;
	uint32_t cru_clksel0;
	uint32_t cru_clksel1;
	uint32_t cru_clksel10;
	uint32_t cru_clksel21;
	uint32_t cru_clkgate[CRU_CLKGATE_CON_CNT];
};

static struct dram_data dram_d;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CRU_BASE, CRU_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GRF_BASE, GRF_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, ISRAM_BASE, ISRAM_SIZE);

static const uint32_t clks_gating_table[CRU_CLKGATE_CON_CNT] = {
	/* gate: 0-3 */
	0xefb8,
	0x0ff7,
	0xfff4,
	0x887f,
	/* gate: 4-7 */
	0x0030,
	0x00f8,
	0x07e0,
	0xc000,
	/* gate: 8-11 */
	0xff84,
	0xb047,
	0x1ca0,
	0x57ff,
	/* gate: 12-15 */
	0x0000,
	0x00ff,
	0x1cc0,
	0x000f,
};

static void clks_disable(void)
{
	uint32_t i;
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	for (i = 0; i < CRU_CLKGATE_CON_CNT; i++) {
		dram_d.cru_clkgate[i] = io_read32(va_base + CRU_CLKGATE_CON(i));
		io_write32(va_base + CRU_CLKGATE_CON(i),
			   BITS_WITH_WMASK(clks_gating_table[i], 0xffff, 0));
	}
}

static void clks_restore(void)
{
	uint32_t i;
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	for (i = 0; i < CRU_CLKGATE_CON_CNT; i++)
		io_write32(va_base + CRU_CLKGATE_CON(i),
			   BITS_WITH_WMASK(dram_d.cru_clkgate[i], 0xffff, 0));
}

static void pll_power_down(uint32_t pll)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	io_write32(va_base + CRU_MODE_CON, PLL_SLOW_MODE(pll));
	io_write32(va_base + CRU_PLL_CON1(pll), PLL_POWER_DOWN);
}

static void pll_power_up(uint32_t pll)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	io_write32(va_base + CRU_PLL_CON1(pll), PLL_POWER_UP);
}

static void pll_wait_lock(uint32_t pll)
{
	uint32_t loop = 0;
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	while (!(io_read32(va_base + CRU_PLL_CON1(pll)) & PLL_LOCK) &&
	       (loop < 500)) {
		udelay(2);
		loop++;
	}

	if (!(io_read32(va_base + CRU_PLL_CON1(pll)) & PLL_LOCK)) {
		EMSG("PLL can't lock, index = %" PRIu32, pll);
		panic();
	}
}

/*
 * Select clock from external 24MHz OSC(slow mode) and power down plls,
 * then set frequency division of relevant bus to 24MHz.
 */
static void plls_power_down(void)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	dram_d.cru_clksel0 = io_read32(va_base + CRU_CLKSEL_CON(0));
	dram_d.cru_clksel1 = io_read32(va_base + CRU_CLKSEL_CON(1));
	dram_d.cru_clksel10 = io_read32(va_base + CRU_CLKSEL_CON(10));
	dram_d.cru_clksel21 = io_read32(va_base + CRU_CLKSEL_CON(21));
	dram_d.cru_mode_con = io_read32(va_base + CRU_MODE_CON);

	pll_power_down(GPLL_ID);
	pll_power_down(CPLL_ID);
	pll_power_down(APLL_ID);

	/* core */
	io_write32(va_base + CRU_CLKSEL_CON(0), BITS_WITH_WMASK(0, 0x1f, 0));
	io_write32(va_base + CRU_CLKSEL_CON(1),
		   BITS_WITH_WMASK(0, 0xf, 0) | BITS_WITH_WMASK(0, 0x7, 4));

	/* peri aclk, hclk, pclk */
	io_write32(va_base + CRU_CLKSEL_CON(10),
		   BITS_WITH_WMASK(0, 0x1f, 0) | BITS_WITH_WMASK(0, 0x3, 8) |
		   BITS_WITH_WMASK(0, 0x7, 12));

	/* pdbus */
	io_write32(va_base + CRU_CLKSEL_CON(0), BITS_WITH_WMASK(0, 0x1f, 8));
	io_write32(va_base + CRU_CLKSEL_CON(1),
		   BITS_WITH_WMASK(0, 0x3, 8) | BITS_WITH_WMASK(0, 0x7, 12));

	/* hdmi cec 32k */
	io_write32(va_base + CRU_CLKSEL_CON(21),
		   BITS_WITH_WMASK(732, 0x3fff, 0) |
		   BITS_WITH_WMASK(2, 0x3, 14));
}

static void plls_restore(void)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	/* power up plls */
	pll_power_up(APLL_ID);
	pll_power_up(GPLL_ID);
	pll_power_up(CPLL_ID);

	udelay(200);

	/* wait lock*/
	pll_wait_lock(APLL_ID);
	pll_wait_lock(GPLL_ID);
	pll_wait_lock(CPLL_ID);

	/* hdmi cec 32k */
	io_write32(va_base + CRU_CLKSEL_CON(21),
		   dram_d.cru_clksel21 | BITS_WMSK(0x3fff, 0) |
		   BITS_WMSK(0x3, 14));

	/* pdbus */
	io_write32(va_base + CRU_CLKSEL_CON(0),
		   dram_d.cru_clksel0 | BITS_WMSK(0x1f, 8));
	io_write32(va_base + CRU_CLKSEL_CON(1),
		   dram_d.cru_clksel1 | BITS_WMSK(0x3, 8) | BITS_WMSK(0x7, 12));

	/* peri aclk, hclk, pclk */
	io_write32(va_base + CRU_CLKSEL_CON(10),
		   dram_d.cru_clksel10 | BITS_WMSK(0x1f, 0) |
		   BITS_WMSK(0x3, 8) | BITS_WMSK(0x7, 12));

	/* core */
	io_write32(va_base + CRU_CLKSEL_CON(0),
		   dram_d.cru_clksel0 | BITS_WMSK(0x1f, 0));
	io_write32(va_base + CRU_CLKSEL_CON(1),
		   dram_d.cru_clksel1 | BITS_WMSK(0xf, 0) | BITS_WMSK(0x7, 4));

	/* resume plls mode */
	io_write32(va_base + CRU_MODE_CON,
		   dram_d.cru_mode_con | BITS_WMSK(0x1, PLL_MODE_BIT(APLL_ID)));
	io_write32(va_base + CRU_MODE_CON,
		   dram_d.cru_mode_con | BITS_WMSK(0x1, PLL_MODE_BIT(CPLL_ID)));
	io_write32(va_base + CRU_MODE_CON,
		   dram_d.cru_mode_con | BITS_WMSK(0x1, PLL_MODE_BIT(GPLL_ID)));
}

static bool wait_core_wfe_i(uint32_t core)
{
	uint32_t wfei_mask, loop = 0;
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(GRF_BASE, GRF_SIZE);

	wfei_mask = CORE_WFE_I_MASK(core);
	while (!(io_read32(va_base + GRF_CPU_STATUS1) & wfei_mask) &&
	       loop < 500) {
		udelay(2);
		loop++;
	}

	return io_read32(va_base + GRF_CPU_STATUS1) & wfei_mask;
}

static bool core_held_in_reset(uint32_t core)
{
	uint32_t val;
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	val = io_read32(va_base + CRU_SOFTRST_CON(0));

	return val & CORE_HELD_IN_RESET(core);
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_CPU_ON:
	case PSCI_CPU_OFF:
	case PSCI_SYSTEM_SUSPEND:
	case PSCI_SYSTEM_RESET:
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

int psci_cpu_on(uint32_t core_idx, uint32_t entry,
		uint32_t context_id)
{
	bool wfei;
	vaddr_t cru_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);
	vaddr_t isram_base = (vaddr_t)phys_to_virt_io(ISRAM_BASE, ISRAM_SIZE);

	core_idx &= MPIDR_CPU_MASK;
	if ((core_idx == 0) || (core_idx >= CFG_TEE_CORE_NB_CORE))
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core_id: %" PRIu32, core_idx);

	/* set secondary cores' NS entry addresses */
	boot_set_core_ns_entry(core_idx, entry, context_id);

	/* wait */
	if (!core_held_in_reset(core_idx)) {
		wfei = wait_core_wfe_i(core_idx);
		if (!wfei) {
			EMSG("Can't wait cpu%" PRIu32 " wfei before softrst",
			     core_idx);
			return PSCI_RET_DENIED;
		}
	}

	/* soft reset core */
	io_write32(cru_base + CRU_SOFTRST_CON(0), CORE_SOFT_RESET(core_idx));
	dsb();

	udelay(2);

	/* soft release core */
	io_write32(cru_base + CRU_SOFTRST_CON(0), CORE_SOFT_RELEASE(core_idx));
	dsb();

	/* wait */
	wfei = wait_core_wfe_i(core_idx);
	if (!wfei) {
		EMSG("Can't wait cpu%" PRIu32 " wfei after softrst", core_idx);
		return PSCI_RET_DENIED;
	}

	/* set secondary secure entry address and lock tag */
	io_write32(isram_base + BOOT_ADDR_OFFSET, TEE_LOAD_ADDR);
	io_write32(isram_base + LOCK_ADDR_OFFSET, LOCK_TAG);
	dsb();

	sev();
	dsb();

	return PSCI_RET_SUCCESS;
}

int psci_cpu_off(void)
{
	uint32_t core = get_core_pos();

	if ((core == 0) || (core >= CFG_TEE_CORE_NB_CORE))
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core_id: %" PRIu32, core);

	psci_armv7_cpu_off();
	thread_mask_exceptions(THREAD_EXCP_ALL);

	while (1)
		wfi();

	return PSCI_RET_INTERNAL_FAILURE;
}

int psci_affinity_info(uint32_t affinity,
		       uint32_t lowest_affnity_level __unused)
{
	uint32_t core_idx = affinity & MPIDR_CPU_MASK;
	uint32_t wfi_mask = CORE_WFI_MASK(core_idx);
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(GRF_BASE, GRF_SIZE);

	DMSG("core_id: %" PRIu32 " STATUS: %" PRIx32 " MASK: %" PRIx32,
	     core_idx, io_read32(va_base + GRF_CPU_STATUS1), wfi_mask);

	return (io_read32(va_base + GRF_CPU_STATUS1) & wfi_mask) ?
		PSCI_AFFINITY_LEVEL_OFF : PSCI_AFFINITY_LEVEL_ON;
}

void psci_system_reset(void)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	/* PLLs enter slow mode */
	io_write32(va_base + CRU_MODE_CON, PLLS_SLOW_MODE);
	dsb();

	/* Global second reset */
	io_write32(va_base + CRU_SNDRST_VAL_BASE, CRU_SNDRST_VAL);
	dsb();
}

int psci_system_suspend(uintptr_t entry __unused,
			uint32_t context_id __unused,
			struct sm_nsec_ctx *nsec __unused)
{
	DMSG("system suspend");

	clks_disable();
	plls_power_down();

	cache_op_inner(DCACHE_CLEAN_INV, NULL, 0);

	wfi();

	plls_restore();
	clks_restore();

	return PSCI_RET_SUCCESS;
}

/* When SMP bootup, we release cores one by one */
static TEE_Result reset_nonboot_cores(void)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	io_write32(va_base + CRU_SOFTRST_CON(0), NONBOOT_CORES_SOFT_RESET);

	return TEE_SUCCESS;
}

service_init_late(reset_nonboot_cores);
