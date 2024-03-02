/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __KERNEL_DELAY_H
#define __KERNEL_DELAY_H

#include <kernel/delay_arch.h>
#include <stdbool.h>
#include <stdint.h>
#include <util.h>

#ifdef CFG_CORE_HAS_GENERIC_TIMER
/* Convert microsecond base delay @us into architecture time tick counts */
static inline uint64_t delay_us2cnt(uint32_t us)
{
	return ((uint64_t)us * (uint64_t)delay_cnt_freq()) / ULL(1000000);
}

/* Return delay tick counter for a timeout expiration in @us microseconds */
static inline uint64_t timeout_init_us(uint32_t us)
{
	return delay_cnt_read() + delay_us2cnt(us);
}

/* Check if timeout tick counter @expire from timeout_init_us() has expired */

static inline bool timeout_elapsed(uint64_t expire)
{
	return delay_cnt_read() > expire;
}

/*
 * Return the time in microseconds since/until timeout tick counter @expired,
 * that was initialized with timeout_init_us() or like, has/will expire.
 * A positive value means the timeout has expired and a negative one it has not.
 */
int timeout_elapsed_us(uint64_t expire);
#endif /*CFG_CORE_HAS_GENERIC_TIMER*/

/* Wait @us microseconds actively polling on architecture timer */
void udelay(uint32_t us);

/* Wait @ms milliseconds actively polling on architecture timer */
void mdelay(uint32_t ms);
#endif
