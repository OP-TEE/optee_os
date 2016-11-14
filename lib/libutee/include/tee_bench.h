/*
 * Copyright (c) 2014, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef TEE_BENCH_H
#define TEE_BENCH_H

#include <inttypes.h>

#define UNUSED(x) (void)(x)

/* max amount of timestamps */
#define TEE_BENCH_MAX_STAMPS	10
#define TEE_BENCH_RB_SIZE (sizeof(struct tee_ringbuf) \
		+ sizeof(struct tee_time_st) * TEE_BENCH_MAX_STAMPS)
#define TEE_BENCH_DEF_PARAM		4

/* OP-TEE susbsystems ids */
#define TEE_BENCH_CLIENT	0x10000000
#define TEE_BENCH_KMOD		0x20000000
#define TEE_BENCH_CORE		0x30000000
#define TEE_BENCH_UTEE		0x40000000
#define TEE_BENCH_UTEE_P1	0x40000001
#define TEE_BENCH_UTEE_P2	0x40000002
#define TEE_BENCH_DUMB_TA	0xF0000001

/* storing timestamps */
struct tee_time_st {
	uint64_t cnt;	/* stores value from CNTPCT register */
	uint64_t addr;	/* stores value from program counter register */
	uint64_t src;	/* OP-TEE subsystem id */
};

/* memory layout for shared memory, where timestamps will be stored */
struct tee_ringbuf {
	uint64_t tm_ind;	/* index of the last timestamp in stamps[] */
	struct tee_time_st stamps[];
};

/* Global ifdef for CFG_TEE_BENCHMARK */
#ifdef CFG_TEE_BENCHMARK

/* Reading program counter */
static inline __attribute__((always_inline)) uintptr_t read_pc(void)
{

	uintptr_t pc;

	asm volatile("mov %0, r15" : "=r"(pc));
	return pc;
}

/* Cycle counter */
static inline uint64_t read_ccounter(void)
{
	uint64_t ccounter = 0;
#if defined(__ARM_ARCH_7A__)
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(ccounter));
#endif /* defined(__ARM_ARCH_7A__) */
	return ccounter;
}

/* Adding timestamp to ringbuffer */
static inline __attribute__((always_inline)) void tee_add_timestamp
				(void *ringbuf_raw, uint32_t source)
{
	struct tee_ringbuf *ringb = (struct tee_ringbuf *)ringbuf_raw;
	uint64_t ts_i;

	if (!ringb)
		return;
	if (ringb->tm_ind >= TEE_BENCH_MAX_STAMPS)
		ringb->tm_ind = 0;

	ts_i = ringb->tm_ind++;
	ringb->stamps[ts_i].cnt = read_ccounter();
	ringb->stamps[ts_i].addr = read_pc();
	ringb->stamps[ts_i].src = source;
}
#else /* CFG_TEE_BENCHMARK */
static inline void tee_add_timestamp
				(void *ringbuf_raw, uint32_t source)
{
	UNUSED(ringbuf_raw);
	UNUSED(source);
}

#endif /* CFG_TEE_BENCHMARK */
#endif /* TEE_BENCH_H */
