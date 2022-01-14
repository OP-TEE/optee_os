// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/wdt.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <matrix.h>
#include <sama5d2.h>
#include <tee_api_types.h>

#define WDT_CR			0x0
#define WDT_CR_KEY		SHIFT_U32(0xA5, 24)
#define WDT_CR_WDRSTT		BIT(0)

#define WDT_MR			0x4
#define WDT_MR_WDV		GENMASK_32(11, 0)
#define WDT_MR_WDV_SET(val)	((val) & WDT_MR_WDV)
#define WDT_MR_WDFIEN		BIT(12)
#define WDT_MR_WDRSTEN		BIT(13)
#define WDT_MR_WDDIS		BIT(15)
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

#define WDT_ENABLED(mr)		(!((mr) & WDT_MR_WDDIS))

struct atmel_wdt {
	struct wdt_chip chip;
	vaddr_t base;
	unsigned long rate;
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

	wdt->mr &= ~WDT_MR_WDV;
	wdt->mr |= WDT_MR_WDV_SET(SEC_TO_WDT(timeout));

	/* WDV and WDD can only be updated when the watchdog is running */
	if (WDT_ENABLED(wdt->mr))
		atmel_wdt_write_sleep(wdt, WDT_MR, wdt->mr);

	return TEE_SUCCESS;
}

static void atmel_wdt_ping(struct wdt_chip *chip)
{
	struct atmel_wdt *wdt = container_of(chip, struct atmel_wdt, chip);

	atmel_wdt_write_sleep(wdt, WDT_CR, WDT_CR_KEY | WDT_CR_WDRSTT);
}

static void atmel_wdt_start(struct atmel_wdt *wdt)
{
	wdt->mr &= ~WDT_MR_WDDIS;
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
	wdt->mr |= WDT_MR_WDDIS;
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
	uint32_t sr = io_read32(wdt->base + WDT_SR);

	if (sr & WDT_SR_DUNF)
		DMSG("Watchdog Underflow !");
	if (sr & WDT_SR_DERR)
		DMSG("Watchdog Error !");

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
	if (!WDT_ENABLED(wdt->mr)) {
		mr = io_read32(wdt->base + WDT_MR);
		if (WDT_ENABLED(mr))
			io_write32(wdt->base + WDT_MR, mr | WDT_MR_WDDIS);
	}

	/* Enable interrupt, and disable watchdog in debug and idle */
	wdt->mr |= WDT_MR_WDFIEN | WDT_MR_WDDBGHLT | WDT_MR_WDIDLEHLT;
	wdt->mr |= WDT_MR_WDD_SET(SEC_TO_WDT(WDT_MAX_TIMEOUT));
	wdt->mr |= WDT_MR_WDV_SET(SEC_TO_WDT(WDT_DEFAULT_TIMEOUT));

	/*
	 * If the watchdog was enabled, write the configuration which will ping
	 * the watchdog.
	 */
	if (WDT_ENABLED(wdt->mr))
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
				 const void *compat_data __unused)
{
	size_t size = 0;
	struct atmel_wdt *wdt;
	uint32_t irq_type = 0;
	uint32_t irq_prio = 0;
	int it = DT_INFO_INVALID_INTERRUPT;
	struct itr_handler *it_hdlr;

	if (_fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_BAD_PARAMETERS;

	matrix_configure_periph_secure(AT91C_ID_WDT);

	wdt = calloc(1, sizeof(*wdt));
	if (!wdt)
		return TEE_ERROR_OUT_OF_MEMORY;

	wdt->chip.ops = &atmel_wdt_ops;

	it = dt_get_irq_type_prio(fdt, node, &irq_type, &irq_prio);
	if (it == DT_INFO_INVALID_INTERRUPT)
		goto err_free_wdt;

	it_hdlr = itr_alloc_add_type_prio(it, &atmel_wdt_itr_cb, 0, wdt,
					  irq_type, irq_prio);
	if (!it_hdlr)
		goto err_free_wdt;

	if (dt_map_dev(fdt, node, &wdt->base, &size) < 0)
		goto err_free_itr_handler;

	/* Get current state of the watchdog */
	wdt->mr = io_read32(wdt->base + WDT_MR) & WDT_MR_WDDIS;

	atmel_wdt_init_hw(wdt);
	itr_enable(it);
	atmel_wdt_register_pm(wdt);

	return watchdog_register(&wdt->chip);

err_free_itr_handler:
	itr_free(it_hdlr);
err_free_wdt:
	free(wdt);

	return TEE_ERROR_GENERIC;
}

static const struct dt_device_match atmel_wdt_match_table[] = {
	{ .compatible = "atmel,sama5d4-wdt" },
	{ }
};

DEFINE_DT_DRIVER(atmel_wdt_dt_driver) = {
	.name = "atmel_wdt",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_wdt_match_table,
	.probe = wdt_node_probe,
};
