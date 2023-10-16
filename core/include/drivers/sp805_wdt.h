/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef __DRIVERS_SP805_WDT_H
#define __DRIVERS_SP805_WDT_H

#include <drivers/wdt.h>
#include <kernel/interrupt.h>
#include <mm/core_memprot.h>
#include <types_ext.h>

/* SP805 register offset */
#define WDT_LOAD_OFFSET		0x000
#define WDT_CONTROL_OFFSET	0x008
#define WDT_INTCLR_OFFSET	0x00c
#define WDT_LOCK_OFFSET		0xc00
#define WDT_SIZE		0xc04

/* Magic word to unlock the wd registers */
#define WDT_UNLOCK_KEY		0x1ACCE551
#define WDT_LOCK_KEY		0x1

/* Register field definitions */
#define WDT_INT_EN		BIT(0)
#define WDT_RESET_EN		BIT(1)
#define WDT_INT_CLR		BIT(0)

#define WDT_LOAD_MIN		0x1

typedef void (*sp805_itr_handler_func_t)(struct wdt_chip *chip);

struct sp805_wdt_data {
	struct io_pa_va base;
	struct wdt_chip chip;
	uint32_t clk_rate;
	uint32_t load_val;
	uint32_t itr_num;
	sp805_itr_handler_func_t itr_handler;
};

/*
 * Initialize sp805 watchdog timer
 *
 * @pd: allocated sp805 watchdog timer platform data
 * @base: physical base address of sp805 watchdog timer
 * @clk_rate: rate of the clock driving the watchdog timer hardware
 * @timeout: watchdog timer timeout in seconds
 * Return a TEE_Result compliant status
 */
TEE_Result sp805_wdt_init(struct sp805_wdt_data *pd, paddr_t base,
		    uint32_t clk_rate, uint32_t timeout);

/*
 * Optionally register sp805 watchdog timer interrupt handler
 *
 * @pd: platform data of sp805 watchdog timer for which interrupt handler
 * is to be registered
 * @itr_num: sp805 watchdog timer interrupt id
 * @itr_flag: interrupt attributes
 * @itr_handler: Optional interrupt handler callback
 * Return a TEE_Result compliant status
 */
TEE_Result sp805_register_itr_handler(struct sp805_wdt_data *pd,
				      uint32_t itr_num, uint32_t itr_flag,
				      sp805_itr_handler_func_t itr_handler);

#endif /* __DRIVERS_SP805_WDT_H */
