/*
 * Copyright (c) 2014, 2015 Linaro Limited
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

#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <trace.h>
#include <kernel/time_source.h>
#include <mm/core_mmu.h>
#include <utee_defines.h>

#include <tee/tee_cryp_utl.h>

#include <stdint.h>
#include <mpa.h>
#include <arm.h>

static TEE_Result arm_cntpct_get_sys_time(TEE_Time *time)
{
	uint64_t cntpct = read_cntpct();
	uint32_t cntfrq = read_cntfrq();

	time->seconds = cntpct / cntfrq;
	time->millis = (cntpct % cntfrq) / (cntfrq / TEE_TIME_MILLIS_BASE);

	return TEE_SUCCESS;
}

static const struct time_source arm_cntpct_time_source = {
	.name = "arm cntpct",
	.protection_level = 1000,
	.get_sys_time = arm_cntpct_get_sys_time,
};

REGISTER_TIME_SOURCE(arm_cntpct_time_source)

/*
 * We collect jitter using cntpct in 32- or 64-bit mode that is typically
 * clocked at around 1MHz.
 *
 * The first time we are called, we add low 16 bits of the counter as entropy.
 *
 * Subsequently, accumulate 2 low bits each time by:
 *
 *  - rotating the accumumlator by 2 bits
 *  - XORing it in 2-bit chunks with the whole CNTPCT contents
 *
 * and adding one byte of entropy when we reach 8 rotated bits.
 */

void plat_prng_add_jitter_entropy(void)
{
	uint64_t tsc = read_cntpct();
	int bytes = 0, n;
	static uint8_t first, bits;
	static uint16_t acc;

	if (!first) {
		acc = tsc;
		bytes = 2;
		first = 1;
	} else {
		acc = (acc << 2) | ((acc >> 6) & 3);
		for (n = 0; n < 64; n += 2)
			acc ^= (tsc >> n) & 3;
		bits += 2;
		if (bits >= 8) {
			bits = 0;
			bytes = 1;
		}
	}
	if (bytes) {
		FMSG("%s: 0x%02X\n", __func__,
		     (int)acc & ((1 << (bytes * 8)) - 1));
		tee_prng_add_entropy((uint8_t *)&acc, bytes);
	}
}
