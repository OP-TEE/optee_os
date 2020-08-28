/*
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SM_TIMER_H_
#define _SM_TIMER_H_

#include <stdint.h>
#ifdef __gnu_linux__
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Change this value to tick rate used by the controller */
#define TICK_RATE_HZ 1000
#define MS_TO_TICKS(msec) (( (msec) * (TICK_RATE_HZ) ) / (1000))

/* function used for delay loops */
uint32_t sm_initSleep(void);
void sm_sleep(uint32_t msec);
void sm_usleep(uint32_t microsec);

#ifdef __cplusplus
}
#endif
#endif // _SM_TIMER_H_
