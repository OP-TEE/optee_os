// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, 2015 Linaro Limited
 */

#include <arm.h>
#include <crypto/crypto.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

TEE_Result tee_time_get_sys_time(TEE_Time *time)
{
	uint64_t cntpct = barrier_read_counter_timer();
	uint32_t cntfrq = read_cntfrq();

	time->seconds = cntpct / cntfrq;
	time->millis = (cntpct % cntfrq) / (cntfrq / TEE_TIME_MILLIS_BASE);

	return TEE_SUCCESS;
}

uint32_t tee_time_get_sys_time_protection_level(void)
{
	return 1000;
}

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

void plat_prng_add_jitter_entropy(enum crypto_rng_src sid, unsigned int *pnum)
{
	uint64_t tsc = barrier_read_counter_timer();
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
		FMSG("0x%02X", (int)acc & ((1 << (bytes * 8)) - 1));
		crypto_rng_add_event(sid, pnum, (uint8_t *)&acc, bytes);
	}
}
