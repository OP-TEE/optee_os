// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <assert.h>
#include <drivers/wdt.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <matrix.h>
#include <mm/core_mmu.h>
#include <tee_api_defines.h>

#define WDT_CR			0x0
#define WDT_CR_KEY		SHIFT_U32(0xA5, 24)
#define WDT_CR_WDRSTT		BIT(0)

#define WDT_MR			0x4
#define WDT_MR_WDV		GENMASK_32(11, 0)
#define WDT_MR_WDV_SET(val)	((val) & WDT_MR_WDV)
#define WDT_MR_WDFIEN		BIT(12)
#define WDT_MR_WDRSTEN		BIT(13)
#define WDT_MR_WDDIS		BIT(15) /* Watchdog Disable of WDT on bit 15 */
#define WDT_MR_WDDIS_DWDT	BIT(12) /* Watchdog Disable of DWDT on bit 12 */
#define WDT_MR_WDD_SHIFT	16
#define WDT_MR_WDD_MASK		GENMASK_32(11, 0)
#define WDT_MR_WDD		SHIFT_U32(WDT_MR_WDD_MASK, WDT_MR_WDD_SHIFT)
#define WDT_MR_WDD_SET(val) \
			SHIFT_U32(((val) & WDT_MR_WDD_MASK), WDT_MR_WDD_SHIFT)
#define WDT_MR_WDDBGHLT		BIT(28)
#define WDT_MR_WDIDLEHLT	BIT(29)

#define WDT_SR			0x8
#define WDT_SR_DUNF		BIT(0)
#define WDT_SR_DERR		BIT(1)

/* DWDT: Watchdog Timer Mode Register */
#define WDT_MR_PERIODRST	BIT(4)
#define WDT_MR_RPTHRST		BIT(5)

/* DWDT: Watchdog Timer Value Register (Read-only) */
#define WDT_VR			0x8
#define WDT_VR_COUNTER_SHIFT	0
#define WDT_VR_COUNTER_MASK	GENMASK_32(11, 0)

/* DWDT: Watchdog Timer Window Level Register */
#define WDT_WL			0xc
#define WDT_WL_RPTH_SHIFT	16
#define WDT_WL_RPTH_MASK	GENMASK_32(27, 16)
#define WDT_WL_PERIOD_SHIFT	0
#define WDT_WL_PERIOD_MASK	GENMASK_32(11, 0)

/* DWDT: Watchdog Timer Interrupt Level Register */
#define WDT_IL			0x10
#define WDT_IL_LVLTH_SHIFT	0
#define WDT_IL_LVLTH_MASK	GENMASK_32(11, 0)

/* DWDT: Watchdog Timer Interrupt Enable/Disable/Status/Mask Register */
#define WDT_IER			0x14
#define WDT_IDR			0x18
#define WDT_ISR			0x1c
#define WDT_IMR			0x20
#define WDT_NSRPTHINT		BIT(4)
#define WDT_NSPERINT		BIT(3)
#define WDT_LVLINT		BIT(2)
#define WDT_RPTHINT		BIT(1)
#define WDT_PERINT		BIT(0)

/*
 * The watchdog is clocked by a 32768Hz clock/128 and the counter is on
 * 12 bits.
 */
#define SLOW_CLOCK_FREQ		(32768)
#define WDT_CLOCK_FREQ		(SLOW_CLOCK_FREQ / 128)
#define WDT_MIN_TIMEOUT		1
#define WDT_MAX_TIMEOUT		(BIT(12) / WDT_CLOCK_FREQ)

#define WDT_DEFAULT_TIMEOUT	WDT_MAX_TIMEOUT

/*
 * We must wait at least 3 clocks period before accessing registers MR and CR.
 * Ensure that we see at least 4 edges
 */
#define WDT_REG_ACCESS_UDELAY	(1000000ULL / SLOW_CLOCK_FREQ * 4)

#define SEC_TO_WDT(sec)		(((sec) * WDT_CLOCK_FREQ) - 1)

#define WDT_ENABLED(mr, dis_mask)	(!((mr) & (dis_mask)))

enum wdt_type {
	WDT_TYPE_WDT,	/* Watchdog Timer */
	WDT_TYPE_DWDT,	/* Dual Watchdog Timer */
};

struct wdt_compat {
	bool wdt_ps; /* Is Peripheral SHDWC Programmable Secure */
	enum wdt_type type; /* Type of Watchdog Timer */
	uint32_t dis_mask; /* Mask of Watchdog Disable in Mode Register */
};

struct atmel_wdt {
	struct wdt_chip chip;
	enum wdt_type type;
	uint32_t dis_mask;
	vaddr_t base;
	uint32_t mr;
	bool enabled;
};

static void atmel_wdt_write_sleep(struct atmel_wdt *wdt, uint32_t reg,
				  uint32_t val)
{
	udelay(WDT_REG_ACCESS_UDELAY);

	io_write32(wdt->base + reg, val);
}

static TEE_Result atmel_wdt_settimeout(struct wdt_chip *chip,
				       unsigned long timeout)
{
	struct atmel_wdt *wdt = container_of(chip, struct atmel_wdt, chip);

	if (wdt->type == WDT_TYPE_WDT) {
		wdt->mr &= ~WDT_MR_WDV;
		wdt->mr |= WDT_MR_WDV_SET(SEC_TO_WDT(timeout));

		/* WDV and WDD only be updated when the watchdog is running */
		if (WDT_ENABLED(wdt->mr, wdt->dis_mask))
			atmel_wdt_write_sleep(wdt, WDT_MR, wdt->mr);
	} else {
		io_write32(wdt->base + WDT_WL,
			   SHIFT_U32(SEC_TO_WDT(timeout), WDT_WL_PERIOD_SHIFT));
	}

	return TEE_SUCCESS;
}

static void atmel_wdt_ping(struct wdt_chip *chip)
{
	struct atmel_wdt *wdt = container_of(chip, struct atmel_wdt, chip);

	atmel_wdt_write_sleep(wdt, WDT_CR, WDT_CR_KEY | WDT_CR_WDRSTT);
}

static void atmel_wdt_start(struct atmel_wdt *wdt)
{
	wdt->mr &= ~wdt->dis_mask;
	atmel_wdt_write_sleep(wdt, WDT_MR, wdt->mr);
}

static void atmel_wdt_enable(struct wdt_chip *chip)
{
	struct atmel_wdt *wdt = container_of(chip, struct atmel_wdt, chip);

	wdt->enabled = true;
	atmel_wdt_start(wdt);
}

static void atmel_wdt_stop(struct atmel_wdt *wdt)
{
	wdt->mr |= wdt->dis_mask;
	atmel_wdt_write_sleep(wdt, WDT_MR, wdt->mr);
}

static void atmel_wdt_disable(struct wdt_chip *chip)
{
	struct atmel_wdt *wdt = container_of(chip, struct atmel_wdt, chip);

	wdt->enabled = false;
	atmel_wdt_stop(wdt);
}

static enum itr_return atmel_wdt_itr_cb(struct itr_handler *h)
{
	struct atmel_wdt *wdt = h->data;
	uint32_t sr = 0;

	if (wdt->type == WDT_TYPE_WDT) {
		sr = io_read32(wdt->base + WDT_SR);

		if (sr & WDT_SR_DUNF)
			DMSG("Watchdog Underflow");
		if (sr & WDT_SR_DERR)
			DMSG("Watchdog Error");
	} else if (wdt->type == WDT_TYPE_DWDT) {
		sr = io_read32(wdt->base + WDT_ISR);

		if (sr & WDT_NSRPTHINT)
			DMSG("NS Watchdog Repeat Threshold Interrupt");
		if (sr & WDT_NSPERINT)
			DMSG("NS Watchdog Period Interrupt");
		if (sr & WDT_LVLINT)
			DMSG("Watchdog Level Threshold Interrupt");
		if (sr & WDT_RPTHINT)
			DMSG("Watchdog Repeat Threshold Interrupt");
		if (sr & WDT_PERINT)
			DMSG("Watchdog Period Interrupt");
	}

	panic("Watchdog interrupt");

	return ITRR_HANDLED;
}

static TEE_Result atmel_wdt_init(struct wdt_chip *chip __unused,
				 unsigned long *min_timeout,
				 unsigned long *max_timeout)
{
	*min_timeout = WDT_MIN_TIMEOUT;
	*max_timeout = WDT_MAX_TIMEOUT;

	return TEE_SUCCESS;
}

static const struct wdt_ops atmel_wdt_ops = {
	.init = atmel_wdt_init,
	.start = atmel_wdt_enable,
	.stop = atmel_wdt_disable,
	.ping = atmel_wdt_ping,
	.set_timeout = atmel_wdt_settimeout,
};

static void atmel_wdt_init_hw(struct atmel_wdt *wdt)
{
	uint32_t mr = 0;

	/*
	 * If we are resuming, we disabled the watchdog on suspend but the
	 * bootloader might have enabled the watchdog. If so, disable it
	 * properly.
	 */
	if (!WDT_ENABLED(wdt->mr, wdt->dis_mask)) {
		mr = io_read32(wdt->base + WDT_MR);
		if (WDT_ENABLED(mr, wdt->dis_mask))
			io_write32(wdt->base + WDT_MR, mr | wdt->dis_mask);
	}

	if (wdt->type == WDT_TYPE_WDT) {
		/* Enable interrupt, and disable watchdog in debug and idle */
		wdt->mr |= WDT_MR_WDFIEN | WDT_MR_WDDBGHLT | WDT_MR_WDIDLEHLT;
		/* Enable watchdog reset */
		wdt->mr |= WDT_MR_WDRSTEN;
		wdt->mr |= WDT_MR_WDD_SET(SEC_TO_WDT(WDT_MAX_TIMEOUT));
		wdt->mr |= WDT_MR_WDV_SET(SEC_TO_WDT(WDT_DEFAULT_TIMEOUT));
	} else if (wdt->type == WDT_TYPE_DWDT) {
		/* Enable interrupt */
		io_write32(wdt->base + WDT_ISR, WDT_PERINT);
		/* Disable watchdog in debug and idle */
		wdt->mr |= WDT_MR_WDDBGHLT | WDT_MR_WDIDLEHLT;
		/* Enable watchdog period reset */
		wdt->mr |= WDT_MR_PERIODRST;
		io_write32(wdt->base + WDT_WL,
			   SHIFT_U32(SEC_TO_WDT(WDT_DEFAULT_TIMEOUT),
				     WDT_WL_PERIOD_SHIFT));
	} else {
		panic("Invalid Watchdog");
	}

	/*
	 * If the watchdog was enabled, write the configuration which will ping
	 * the watchdog.
	 */
	if (WDT_ENABLED(wdt->mr, wdt->dis_mask))
		io_write32(wdt->base + WDT_MR, wdt->mr);
}

#ifdef CFG_PM_ARM32
static TEE_Result atmel_wdt_pm(enum pm_op op, uint32_t pm_hint __unused,
			       const struct pm_callback_handle *hdl)
{
	struct atmel_wdt *wdt = hdl->handle;

	switch (op) {
	case PM_OP_RESUME:
		atmel_wdt_init_hw(wdt);
		if (wdt->enabled)
			atmel_wdt_start(wdt);
		break;
	case PM_OP_SUSPEND:
		if (wdt->enabled)
			atmel_wdt_stop(wdt);
		break;
	default:
		panic("Invalid PM operation");
	}

	return TEE_SUCCESS;
}

static void atmel_wdt_register_pm(struct atmel_wdt *wdt)
{
	register_pm_driver_cb(atmel_wdt_pm, wdt, "atmel_wdt");
}
#else
static void atmel_wdt_register_pm(struct atmel_wdt *wdt __unused)
{
}
#endif

static TEE_Result wdt_node_probe(const void *fdt, int node,
				 const void *compat_data)
{
	const struct wdt_compat *compat = compat_data;
	size_t size = 0;
	struct atmel_wdt *wdt;
	uint32_t irq_type = 0;
	uint32_t irq_prio = 0;
	int it = DT_INFO_INVALID_INTERRUPT;
	struct itr_handler *it_hdlr = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_BAD_PARAMETERS;

	if (compat->wdt_ps)
		matrix_configure_periph_secure(AT91C_ID_WDT);

	wdt = calloc(1, sizeof(*wdt));
	if (!wdt)
		return TEE_ERROR_OUT_OF_MEMORY;

	wdt->chip.ops = &atmel_wdt_ops;
	wdt->type = compat->type;
	wdt->dis_mask = compat->dis_mask;

	it = dt_get_irq_type_prio(fdt, node, &irq_type, &irq_prio);
	if (it == DT_INFO_INVALID_INTERRUPT)
		goto err_free;

	res = interrupt_alloc_add_conf_handler(interrupt_get_main_chip(),
					       it, atmel_wdt_itr_cb, 0, wdt,
					       irq_type, irq_prio, &it_hdlr);
	if (res)
		goto err_free;

	if (dt_map_dev(fdt, node, &wdt->base, &size, DT_MAP_AUTO) < 0)
		goto err_remove_handler;

	/* Get current state of the watchdog */
	wdt->mr = io_read32(wdt->base + WDT_MR) & wdt->dis_mask;

	atmel_wdt_init_hw(wdt);
	interrupt_enable(it_hdlr->chip, it_hdlr->it);

	res = watchdog_register(&wdt->chip);
	if (res)
		goto err_disable_unmap;

	atmel_wdt_register_pm(wdt);

	return TEE_SUCCESS;

err_disable_unmap:
	interrupt_disable(it_hdlr->chip, it_hdlr->it);
	core_mmu_remove_mapping(MEM_AREA_IO_SEC, (void *)wdt->base, size);
err_remove_handler:
	interrupt_remove_free_handler(it_hdlr);
err_free:
	free(wdt);

	return TEE_ERROR_GENERIC;
}

static const struct wdt_compat sama5d2_compat = {
	.wdt_ps = true,
	.type = WDT_TYPE_WDT,
	.dis_mask = WDT_MR_WDDIS,
};

static const struct wdt_compat sama7g5_compat = {
	.wdt_ps = false,
	.type = WDT_TYPE_DWDT,
	.dis_mask = WDT_MR_WDDIS_DWDT,
};

static const struct dt_device_match atmel_wdt_match_table[] = {
	{
		.compatible = "atmel,sama5d4-wdt",
		.compat_data = &sama5d2_compat,
	},
	{
		.compatible = "microchip,sama7g5-wdt",
		.compat_data = &sama7g5_compat,
	},
	{ }
};

DEFINE_DT_DRIVER(atmel_wdt_dt_driver) = {
	.name = "atmel_wdt",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_wdt_match_table,
	.probe = wdt_node_probe,
};
