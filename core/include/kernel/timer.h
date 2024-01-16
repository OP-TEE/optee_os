/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, Linaro Limited
 */

#ifndef __KERNEL_TIMER_H
#define __KERNEL_TIMER_H

void generic_timer_start(uint32_t time_ms);
void generic_timer_stop(void);

/* Handler for timer expiry interrupt */
void generic_timer_handler(uint32_t time_ms);

#endif /* __KERNEL_TIMER_H */
