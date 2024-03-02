// SPDX-License-Identifier: BSD-2-Clause
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

#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/misc.h>

#ifdef CFG_CORE_HAS_GENERIC_TIMER
int timeout_elapsed_us(uint64_t expire)
{
	int64_t diff = delay_cnt_read() - expire;

	if (MUL_OVERFLOW(diff, 1000000, &diff) ||
	    diff < INT_MIN || diff > INT_MAX) {
		if (timeout_elapsed(expire))
			return INT_MAX;
		else
			return INT_MIN;
	}

	return diff / delay_cnt_freq();
}

void udelay(uint32_t us)
{
	uint64_t target = timeout_init_us(us);

	while (!timeout_elapsed(target))
		;
}
#else

void udelay(uint32_t us)
{
	uint64_t cycles = 0;
	uint32_t cycles_to_wait = 0;

	cycles = (uint64_t)us * ((uint64_t)plat_get_freq() / 1000000ULL);

	while (cycles) {
		cycles_to_wait = MIN(cycles, UINT32_MAX);
		wait_cycles(cycles_to_wait);
		cycles -= cycles_to_wait;
	}
}
#endif

void mdelay(uint32_t ms)
{
	udelay(1000 * ms);
}
