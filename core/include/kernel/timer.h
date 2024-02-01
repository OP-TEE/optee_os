/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, 2024, Linaro Limited
 */

#ifndef __KERNEL_TIMER_H
#define __KERNEL_TIMER_H

#include <kernel/interrupt.h>
#include <types_ext.h>

void generic_timer_start(uint32_t time_ms);
void generic_timer_stop(void);

/* Handler for timer expiry interrupt */
void generic_timer_handler(uint32_t time_ms);

/*
 * timer_init_callout_service() - Initializes the callout service
 * @itr_chip:	Interrupt chip, typically interrupt_get_main_chip()
 * @itr_number:	Interrupt number in @itr_chip space for the timer.
 *
 * This function starts the callout service via interrupts from the timer.
 * The platform or architecture specific code provides the implementation
 * of this function. The interrupt callback function for the timer calls
 * callout_service_cb() to drive the callout service.
 *
 * Note that usage of this function is incompatible with usage of the
 * generic_timer_start(), generic_timer_stop() and generic_timer_handler()
 * functions.
 */
void timer_init_callout_service(struct itr_chip *itr_chip, size_t itr_number);

#endif /* __KERNEL_TIMER_H */
