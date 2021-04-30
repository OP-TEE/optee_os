/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef BENCH_H
#define BENCH_H

#include <inttypes.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <optee_msg.h>

/*
 * Cycle count divider is enabled (in PMCR),
 * CCNT value is incremented every 64th clock cycle
 */
#define TEE_BENCH_DIVIDER		U(64)

/* Max amount of timestamps per buffer */
#define TEE_BENCH_MAX_STAMPS		U(32)
#define TEE_BENCH_MAX_MASK		(TEE_BENCH_MAX_STAMPS - 1)

#define OPTEE_MSG_RPC_CMD_BENCH_REG_NEW		U(0)
#define OPTEE_MSG_RPC_CMD_BENCH_REG_DEL		U(1)

/* OP-TEE susbsystems ids */
#define TEE_BENCH_CLIENT	U(0x10000000)
#define TEE_BENCH_KMOD		U(0x20000000)
#define TEE_BENCH_CORE		U(0x30000000)
#define TEE_BENCH_UTEE		U(0x40000000)
#define TEE_BENCH_DUMB_TA	U(0xF0000001)

/* storing timestamp */
struct tee_time_st {
	uint64_t cnt;	/* stores value from CNTPCT register */
	uint64_t addr;	/* stores value from program counter register */
	uint64_t src;	/* OP-TEE subsystem id */
};

/* per-cpu circular buffer for timestamps */
struct tee_ts_cpu_buf {
	uint64_t head;
	uint64_t tail;
	struct tee_time_st stamps[TEE_BENCH_MAX_STAMPS];
};

/* memory layout for shared memory, where timestamps will be stored */
struct tee_ts_global {
	uint64_t cores;
	struct tee_ts_cpu_buf cpu_buf[];
};

#ifdef CFG_TEE_BENCHMARK
void bm_timestamp(void);
#else
static inline void bm_timestamp(void) {}
#endif /* CFG_TEE_BENCHMARK */

#endif /* BENCH_H */
