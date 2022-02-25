/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018-2022, Linaro Limited
 */

#ifndef __TIMER_H
#define __TIMER_H

#include <stdint.h>
#include <tee_api_types.h>

/* Enable generic timer to the targe telpasure time */
TEE_Result generic_timer_start(uint32_t time_ms);

/* Disable generic timer */
TEE_Result generic_timer_stop(void);

/* Reload timer from interrupt context for the next event */
TEE_Result generic_timer_handler(uint32_t time_ms);

#endif /* __TIMER_H */
