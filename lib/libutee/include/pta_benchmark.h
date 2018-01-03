/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __PTA_BENCHMARK_H
#define __PTA_BENCHMARK_H

/*
 * Interface to the benchmark pseudo-TA, which is used for registering
 * timestamp buffers
 */

#define BENCHMARK_UUID \
		{ 0x0b9a63b0, 0xb4c6, 0x4c85, \
		{ 0xa2, 0x84, 0xa2, 0x28, 0xef, 0x54, 0x7b, 0x4e } }

/*
 * Benchmark PTA supported commands
 */
#define BENCHMARK_CMD(id)	(0xFA190000 | ((id) & 0xFFFF))
#define BENCHMARK_CMD_ALLOCATE_BUF		BENCHMARK_CMD(1)
#define BENCHMARK_CMD_GET_MEMREF		BENCHMARK_CMD(2)
#define BENCHMARK_CMD_UNREGISTER		BENCHMARK_CMD(3)

#endif /* __PTA_BENCHMARK_H */
