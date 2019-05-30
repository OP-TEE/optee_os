// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Broadcom
 *
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

	return io_pa_or_va(&pd->base);
}

/* This routine finds load value that will reset system in required timeout */
static void sp805_setload(struct wdt_chip *chip, unsigned long timeout)
{
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);
	uint32_t load;

	/*
	 * sp805 runs counter with given value twice, after the end of first
	 * counter it gives an interrupt and then starts counter again. If
	 * interrupt already occurred then it resets the system. This is why
	 * load is half of what should be required.
	 */
	load = (pd->clk_rate / 2) * (timeout) - 1;

	load = (load > WDT_LOAD_MAX) ? WDT_LOAD_MAX : load;
	load = (load < WDT_LOAD_MIN) ? WDT_LOAD_MIN : load;

	pd->load_val = load;
}

static void sp805_config(struct wdt_chip *chip, bool ping)
{
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);
	vaddr_t base = chip_to_base(chip);

	io_write32(base + WDT_LOCK_OFFSET, WDT_UNLOCK_KEY);
	io_write32(base + WDT_LOAD_OFFSET, pd->load_val);
	io_write32(base + WDT_INTCLR_OFFSET, WDT_INT_CLR);

	if (!ping)
		io_write32(base + WDT_CONTROL_OFFSET,
			   WDT_INT_EN | WDT_RESET_EN);

	io_write32(base + WDT_LOCK_OFFSET, WDT_LOCK_KEY);

	/* Flush posted writes. */
	io_read32(base + WDT_LOCK_OFFSET);
}

static void sp805_ping(struct wdt_chip *chip)
{
	sp805_config(chip, true);
}

/* enables watchdog timers reset */
static void sp805_enable(struct wdt_chip *chip)
{
	sp805_config(chip, false);
}

/* disables watchdog timers reset */
static void sp805_disable(struct wdt_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	io_write32(base + WDT_LOCK_OFFSET, WDT_UNLOCK_KEY);
	io_write32(base + WDT_CONTROL_OFFSET, 0);
	io_write32(base + WDT_LOCK_OFFSET, WDT_LOCK_KEY);

	/* Flush posted writes. */
	io_read32(base + WDT_LOCK_OFFSET);
}

static enum itr_return wdt_irq_cb(struct itr_handler *h __unused)
{
	struct wdt_chip *chip = h->data;
	struct sp805_wdt_data *pd =
		container_of(chip, struct sp805_wdt_data, chip);

	if (pd->irq_handler)
		pd->irq_handler(h);

	return ITRR_HANDLED;
}

TEE_Result sp805_register_irq_handler(struct sp805_wdt_data *pd,
				      uint32_t irq_num, uint32_t irq_flags,
				      irq_handler_t irq_handler)
{
	struct itr_handler *wdt_irq = &pd->chip.wdt_irq;

	wdt_irq->it = irq_num;
	wdt_irq->flags = irq_flags;
	wdt_irq->handler = wdt_irq_cb;
	wdt_irq->data = &pd->chip;
	pd->irq_handler = irq_handler;

	itr_add(wdt_irq);
	itr_enable(wdt_irq->it);

	return TEE_SUCCESS;
}

static struct wdt_ops sp805_wdt_ops = {
	.start = sp805_enable,
	.stop = sp805_disable,
	.ping = sp805_ping,
	.set_timeout = sp805_setload,
};
KEEP_PAGER(sp805_wdt_ops);

void sp805_wdt_init(struct sp805_wdt_data *pd, paddr_t base,
		    uint32_t clk_rate, uint32_t timeout)
{
	assert(pd);
	pd->base.pa = base;
	pd->clk_rate = clk_rate;
	pd->chip.ops = &sp805_wdt_ops;
	sp805_setload(&pd->chip, timeout);
}
