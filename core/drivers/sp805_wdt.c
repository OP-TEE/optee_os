// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Broadcom
 */

#include <drivers/sp805_wdt.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <trace.h>

static vaddr_t chip_to_base(struct wdt_chip *chip)
{
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);

	return io_pa_or_va(&pd->base, WDT_SIZE);
}

static TEE_Result sp805_setload(struct wdt_chip *chip, unsigned long timeout)
{
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);
	uint32_t load = 0;

	/*
	 * sp805 runs counter with given value twice, after the end of first
	 * counter it gives an interrupt and then starts counter again. If
	 * interrupt already occurred then it resets the system. This is why
	 * load is half of what should be required.
	 */
	if (MUL_OVERFLOW(timeout, pd->clk_rate, &load))
		return TEE_ERROR_SECURITY;

	load =  (load / 2) - 1;
	if (load < WDT_LOAD_MIN)
		load = WDT_LOAD_MIN;

	pd->load_val = load;
	return TEE_SUCCESS;
}

static void sp805_config(struct wdt_chip *chip, bool enable)
{
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);
	vaddr_t base = chip_to_base(chip);

	io_write32(base + WDT_LOCK_OFFSET, WDT_UNLOCK_KEY);
	io_write32(base + WDT_LOAD_OFFSET, pd->load_val);
	io_write32(base + WDT_INTCLR_OFFSET, WDT_INT_CLR);

	if (enable)
		io_write32(base + WDT_CONTROL_OFFSET,
			   WDT_INT_EN | WDT_RESET_EN);

	io_write32(base + WDT_LOCK_OFFSET, WDT_LOCK_KEY);

	/* Flush posted writes. */
	(void)io_read32(base + WDT_LOCK_OFFSET);
}

static void sp805_ping(struct wdt_chip *chip)
{
	sp805_config(chip, false);
}

static void sp805_enable(struct wdt_chip *chip)
{
	sp805_config(chip, true);
}

static void sp805_disable(struct wdt_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	io_write32(base + WDT_LOCK_OFFSET, WDT_UNLOCK_KEY);
	io_write32(base + WDT_CONTROL_OFFSET, 0);
	io_write32(base + WDT_LOCK_OFFSET, WDT_LOCK_KEY);

	/* Flush posted writes. */
	(void)io_read32(base + WDT_LOCK_OFFSET);
}

static enum itr_return wdt_itr_cb(struct itr_handler *h)
{
	struct wdt_chip *chip = h->data;
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);

	if (pd->itr_handler)
		pd->itr_handler(chip);

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(wdt_itr_cb);

TEE_Result sp805_register_itr_handler(struct sp805_wdt_data *pd,
				      uint32_t itr_num, uint32_t itr_flags,
				      sp805_itr_handler_func_t itr_handler)
{
	struct itr_handler *wdt_itr;

	assert(!pd->chip.wdt_itr);

	wdt_itr = itr_alloc_add(itr_num, wdt_itr_cb,
				itr_flags, &pd->chip);
	if (!wdt_itr)
		return TEE_ERROR_OUT_OF_MEMORY;

	pd->itr_handler = itr_handler;
	pd->chip.wdt_itr = wdt_itr;

	itr_enable(wdt_itr->it);

	return TEE_SUCCESS;
}

static const struct wdt_ops sp805_wdt_ops = {
	.start = sp805_enable,
	.stop = sp805_disable,
	.ping = sp805_ping,
	.set_timeout = sp805_setload,
};
DECLARE_KEEP_PAGER(sp805_wdt_ops);

TEE_Result sp805_wdt_init(struct sp805_wdt_data *pd, paddr_t base,
		    uint32_t clk_rate, uint32_t timeout)
{
	assert(pd);
	pd->base.pa = base;
	pd->clk_rate = clk_rate;
	pd->chip.ops = &sp805_wdt_ops;
	return sp805_setload(&pd->chip, timeout);
}
