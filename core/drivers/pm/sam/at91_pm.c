// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <assert.h>
#include <at91_clk.h>
#include <drivers/atmel_shdwc.h>
#include <drivers/pm/sam/atmel_pm.h>
#include <drivers/sam/at91_ddr.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <matrix.h>
#include <mm/core_memprot.h>
#include <smc_ids.h>
#include <sm/pm.h>
#include <stdbool.h>
#include <tee_api_types.h>

#include "at91_pm.h"

#if CFG_ATMEL_PM_SUSPEND_MODE < AT91_PM_STANDBY || \
	CFG_ATMEL_PM_SUSPEND_MODE > AT91_PM_BACKUP
#error Invalid suspend mode, please check CFG_ATMEL_PM_SUSPEND_MODE
#endif

#define AT91_SECUMOD_SYSR		0x04
#define AT91_SECUMOD_RAMRDY		0x14
#define AT91_SECUMOD_RAMRDY_READY	BIT(0)

static struct at91_pm_data soc_pm;

/* Backup canary */
static uint32_t canary = 0xA5A5A5A5;

/* Backup mode information used by at91bootstrap */
static struct at91bootstrap_bu {
	uint32_t suspended;
	uint32_t reserved;
	uint32_t *canary;
	uint32_t resume;
} *at91bootstrap_bu;

static vaddr_t at91_suspend_sram_base;
static void (*at91_suspend_sram_fn)(struct at91_pm_data *);

enum sm_handler_ret at91_pm_set_suspend_mode(struct thread_smc_args *args)
{
	unsigned int mode = args->a1;

	/*
	 * We don't expect this function to be called simultaneously while we
	 * are entering suspend/resume function. On sama5d2, this is not a
	 * problem since this SoC is a single core one but in order to prevent
	 * any other SoC support to be added without handling this concurrency,
	 * check that we are compiled for a single core.
	 */
	COMPILE_TIME_ASSERT(CFG_TEE_CORE_NB_CORE == 1);

	if (mode > AT91_PM_BACKUP) {
		args->a0 = SAMA5_SMC_SIP_RETURN_EINVAL;
		return SM_HANDLER_SMC_HANDLED;
	}
	DMSG("Setting suspend mode to %u", mode);

	args->a0 = SAMA5_SMC_SIP_RETURN_SUCCESS;
	soc_pm.mode = mode;

	return SM_HANDLER_SMC_HANDLED;
}

enum sm_handler_ret at91_pm_get_suspend_mode(struct thread_smc_args *args)
{
	args->a1 = soc_pm.mode;
	args->a0 = SAMA5_SMC_SIP_RETURN_SUCCESS;

	return SM_HANDLER_SMC_HANDLED;
}

static void at91_pm_copy_suspend_to_sram(void)
{
	memcpy((void *)at91_suspend_sram_base, &at91_pm_suspend_in_sram,
	       at91_pm_suspend_in_sram_sz);

	cache_op_inner(DCACHE_AREA_CLEAN, (void *)at91_suspend_sram_base,
		       at91_pm_suspend_in_sram_sz);
	cache_op_inner(ICACHE_AREA_INVALIDATE, at91_suspend_sram_fn,
		       at91_pm_suspend_in_sram_sz);
}

void atmel_pm_cpu_idle(void)
{
	uint32_t lpr0 = 0;
	uint32_t saved_lpr0 = 0;

	saved_lpr0 = io_read32(soc_pm.ramc + AT91_DDRSDRC_LPR);
	lpr0 = saved_lpr0 & ~AT91_DDRSDRC_LPCB;
	lpr0 |= AT91_DDRSDRC_LPCB_POWER_DOWN;

	io_write32(soc_pm.ramc + AT91_DDRSDRC_LPR, lpr0);

	cpu_idle();

	io_write32(soc_pm.ramc + AT91_DDRSDRC_LPR, saved_lpr0);
}

static void at91_sama5d2_config_shdwc_ws(vaddr_t shdwc, uint32_t *mode,
					 uint32_t *polarity)
{
	uint32_t val = 0;

	/* SHDWC.WUIR */
	val = io_read32(shdwc + AT91_SHDW_WUIR);
	*mode |= val & AT91_SHDW_WKUPEN_MASK;
	*polarity |= (val >> AT91_SHDW_WKUPT_SHIFT) & AT91_SHDW_WKUPT_MASK;
}

static int at91_sama5d2_config_pmc_ws(vaddr_t pmc, uint32_t mode,
				      uint32_t polarity)
{
	io_write32(pmc + AT91_PMC_FSMR, mode);
	io_write32(pmc + AT91_PMC_FSPR, polarity);

	return 0;
}

struct wakeup_source_info {
	unsigned int pmc_fsmr_bit;
	unsigned int shdwc_mr_bit;
	bool set_polarity;
};

static const struct wakeup_source_info ws_info[] = {
	{ .pmc_fsmr_bit = AT91_PMC_FSTT(10),	.set_polarity = true },
	{ .pmc_fsmr_bit = AT91_PMC_RTCAL,	.shdwc_mr_bit = BIT(17) },
	{ .pmc_fsmr_bit = AT91_PMC_USBAL },
	{ .pmc_fsmr_bit = AT91_PMC_SDMMC_CD },
};

struct wakeup_src {
	const char *compatible;
	const struct wakeup_source_info *info;
};

static const struct wakeup_src sama5d2_ws_ids[] = {
	{ .compatible = "atmel,sama5d2-gem",		.info = &ws_info[0] },
	{ .compatible = "atmel,at91rm9200-rtc",		.info = &ws_info[1] },
	{ .compatible = "atmel,sama5d3-udc",		.info = &ws_info[2] },
	{ .compatible = "atmel,at91rm9200-ohci",	.info = &ws_info[2] },
	{ .compatible = "usb-ohci",			.info = &ws_info[2] },
	{ .compatible = "atmel,at91sam9g45-ehci",	.info = &ws_info[2] },
	{ .compatible = "usb-ehci",			.info = &ws_info[2] },
	{ .compatible = "atmel,sama5d2-sdhci",		.info = &ws_info[3] }
};

static bool dev_is_wakeup_source(const void *fdt, int node)
{
	return fdt_get_property(fdt, node, "wakeup-source", NULL);
}

static int at91_pm_config_ws_ulp1(bool set)
{
	const struct wakeup_source_info *wsi = NULL;
	const struct wakeup_src *wsrc = NULL;
	unsigned int polarity = 0;
	unsigned int mode = 0;
	unsigned int val = 0;
	unsigned int src = 0;
	int node = 0;

	if (!set) {
		io_write32(soc_pm.pmc + AT91_PMC_FSMR, mode);
		return TEE_SUCCESS;
	}

	at91_sama5d2_config_shdwc_ws(soc_pm.shdwc, &mode, &polarity);

	val = io_read32(soc_pm.shdwc + AT91_SHDW_MR);

	/* Loop through defined wakeup sources. */
	for (src = 0; src < ARRAY_SIZE(sama5d2_ws_ids); src++) {
		wsrc = &sama5d2_ws_ids[src];
		wsi = wsrc->info;

		node = fdt_node_offset_by_compatible(soc_pm.fdt, -1,
						     wsrc->compatible);
		while (node >= 0) {
			if (dev_is_wakeup_source(soc_pm.fdt, node)) {
				/* Check if enabled on SHDWC. */
				if (wsi->shdwc_mr_bit &&
				    !(val & wsi->shdwc_mr_bit))
					goto next_node;

				mode |= wsi->pmc_fsmr_bit;
				if (wsi->set_polarity)
					polarity |= wsi->pmc_fsmr_bit;
			}
next_node:
			node = fdt_node_offset_by_compatible(soc_pm.fdt, node,
							     wsrc->compatible);
		}
	}

	if (!mode) {
		EMSG("AT91: PM: no ULP1 wakeup sources found!");
		return TEE_ERROR_BAD_STATE;
	}

	at91_sama5d2_config_pmc_ws(soc_pm.pmc, mode, polarity);

	return TEE_SUCCESS;
}

/*
 * Verify that all the clocks are correct before entering
 * slow-clock mode.
 */
static bool at91_pm_verify_clocks(void)
{
	int i = 0;
	uint32_t scsr = 0;

	scsr = io_read32(soc_pm.pmc + AT91_PMC_SCSR);

	/* USB must not be using PLLB */
	if ((scsr & (AT91SAM926x_PMC_UHP | AT91SAM926x_PMC_UDP)) != 0) {
		EMSG("AT91: PM - Suspend-to-RAM with USB still active");
		return false;
	}

	/* PCK0..PCK3 must be disabled, or configured to use clk32k */
	for (i = 0; i < 4; i++) {
		uint32_t css = 0;

		if ((scsr & (AT91_PMC_PCK0 << i)) == 0)
			continue;
		css = io_read32(soc_pm.pmc + AT91_PMC_PCKR(i)) & AT91_PMC_CSS;
		if (css != AT91_PMC_CSS_SLOW) {
			EMSG("AT91: PM - Suspend-to-RAM with PCK%d src %"PRId32,
			     i, css);
			return false;
		}
	}

	return true;
}

static TEE_Result at91_write_backup_data(void)
{
	uint32_t val = 0;

	while (true) {
		val = io_read32(soc_pm.secumod + AT91_SECUMOD_RAMRDY);
		if (val & AT91_SECUMOD_RAMRDY_READY)
			break;
	}

	io_write32((vaddr_t)&at91bootstrap_bu->suspended, 1);
	io_write32((vaddr_t)&at91bootstrap_bu->canary, virt_to_phys(&canary));
	io_write32((vaddr_t)&at91bootstrap_bu->resume,
		   virt_to_phys((void *)(vaddr_t)at91_pm_cpu_resume));

	return TEE_SUCCESS;
}

static TEE_Result at91_enter_backup(void)
{
	int ret = -1;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = at91_write_backup_data();
	if (res)
		return res;

	pm_change_state(PM_OP_SUSPEND, 0);
	ret = sm_pm_cpu_suspend((uint32_t)&soc_pm,
				(void *)at91_suspend_sram_fn);
	if (ret < 0) {
		DMSG("Suspend failed");
		res = TEE_ERROR_BAD_STATE;
	} else {
		res = TEE_SUCCESS;
	}

	pm_change_state(PM_OP_RESUME, 0);
	if (res)
		return res;

	/* SRAM content is lost after resume */
	at91_pm_copy_suspend_to_sram();

	return TEE_SUCCESS;
}

TEE_Result atmel_pm_suspend(uintptr_t entry, struct sm_nsec_ctx *nsec)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	DMSG("Entering suspend mode %d", soc_pm.mode);

	if (soc_pm.mode >= AT91_PM_ULP0) {
		if (!at91_pm_verify_clocks())
			return TEE_ERROR_BAD_STATE;
	}

	if (soc_pm.mode == AT91_PM_ULP1)
		at91_pm_config_ws_ulp1(true);

	sm_save_unbanked_regs(&nsec->ub_regs);

	if (soc_pm.mode == AT91_PM_BACKUP) {
		res = at91_enter_backup();
	} else {
		at91_suspend_sram_fn(&soc_pm);
		res = TEE_SUCCESS;
	}

	if (soc_pm.mode == AT91_PM_ULP1)
		at91_pm_config_ws_ulp1(false);

	sm_restore_unbanked_regs(&nsec->ub_regs);

	/*
	 * If the system went to backup mode, register state was lost and must
	 * be restored by jumping to the user provided entry point
	 */
	if (res == TEE_SUCCESS && soc_pm.mode == AT91_PM_BACKUP)
		nsec->mon_lr = entry;

	DMSG("Exiting suspend mode %d, res %"PRIx32, soc_pm.mode, res);

	return res;
}

static TEE_Result at91_pm_dt_dram_init(const void *fdt)
{
	int node = -1;
	size_t size = 0;

	node = fdt_node_offset_by_compatible(fdt, -1, "atmel,sama5d3-ddramc");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (dt_map_dev(fdt, node, &soc_pm.ramc, &size) < 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result at91_pm_backup_init(const void *fdt)
{
	int node = -1;
	size_t size = 0;

	node = fdt_node_offset_by_compatible(fdt, -1, "atmel,sama5d2-sfrbu");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (dt_map_dev(fdt, node, &soc_pm.sfrbu, &size) < 0)
		return TEE_ERROR_GENERIC;

	if (_fdt_get_status(fdt, node) == DT_STATUS_OK_SEC)
		matrix_configure_periph_secure(AT91C_ID_SFRBU);

	return TEE_SUCCESS;
}

static TEE_Result at91_pm_sram_init(const void *fdt)
{
	int node = -1;
	size_t size = 0;
	paddr_t at91_suspend_sram_pbase;
	size_t suspend_sz = at91_pm_suspend_in_sram_sz;

	node = fdt_node_offset_by_compatible(fdt, -1, "atmel,sama5d2-sram");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (_fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_GENERIC;

	if (dt_map_dev(fdt, node, &at91_suspend_sram_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	at91_suspend_sram_pbase = virt_to_phys((void *)at91_suspend_sram_base);

	/* Map the secure ram suspend code to be executable */
	at91_suspend_sram_fn = core_mmu_add_mapping(MEM_AREA_TEE_RAM,
						    at91_suspend_sram_pbase,
						    suspend_sz);
	if (!at91_suspend_sram_fn) {
		EMSG("Failed to remap sram as executable");
		return TEE_ERROR_GENERIC;
	}

	at91_pm_copy_suspend_to_sram();

	return TEE_SUCCESS;
}

static TEE_Result at91_securam_init(const void *fdt)
{
	int node = -1;
	size_t size = 0;
	struct clk *clk = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	node = fdt_node_offset_by_compatible(fdt, -1, "atmel,sama5d2-securam");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (_fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_GENERIC;

	if (dt_map_dev(fdt, node, &soc_pm.securam, &size) < 0)
		return TEE_ERROR_GENERIC;

	res = clk_dt_get_by_index(fdt, node, 0, &clk);
	if (res)
		return res;

	if (clk_enable(clk))
		return TEE_ERROR_GENERIC;

	if (size < sizeof(struct at91bootstrap_bu))
		return TEE_ERROR_SHORT_BUFFER;

	at91bootstrap_bu = (void *)soc_pm.securam;

	node = fdt_node_offset_by_compatible(fdt, -1, "atmel,sama5d2-secumod");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (_fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_GENERIC;

	if (dt_map_dev(fdt, node, &soc_pm.secumod, &size) < 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result sama5d2_pm_init_all(const void *fdt, vaddr_t shdwc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	soc_pm.fdt = fdt;
	soc_pm.shdwc = shdwc;
	soc_pm.pmc = at91_pmc_get_base();
	if (!soc_pm.pmc)
		return TEE_ERROR_GENERIC;

	soc_pm.mode = CFG_ATMEL_PM_SUSPEND_MODE;

	res = at91_securam_init(fdt);
	if (res)
		return res;

	res = at91_pm_dt_dram_init(fdt);
	if (res)
		return res;

	res = at91_pm_backup_init(fdt);
	if (res)
		return res;

	res = at91_pm_sram_init(fdt);
	if (res)
		return res;

	return TEE_SUCCESS;
}

TEE_Result sama5d2_pm_init(const void *fdt, vaddr_t shdwc)
{
	if (sama5d2_pm_init_all(fdt, shdwc))
		panic("Failed to setup PM for sama5d2");

	return TEE_SUCCESS;
}
