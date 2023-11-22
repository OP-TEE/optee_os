/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, STMicroelectronics
 * Copyright (C) 2022, Microchip
 */
#ifndef __PTA_STATS_H
#define __PTA_STATS_H

#define STATS_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define STATS_CMD_PAGER_STATS		0
#define STATS_CMD_ALLOC_STATS		1
#define STATS_CMD_MEMLEAK_STATS		2
/*
 * UTEE_ENTRY_FUNC_DUMP_MEMSTATS
 * [out]    memref[0]        Array of context information of loaded TAs
 *
 * Each cell of the TA information array contains:
 * TEE_UUID    TA UUID
 * uint32_t    Non zero if TA panicked, 0 otherwise
 * uint32_t    Number of sessions opened by the TA
 * uint32_t    Byte size currently allocated in TA heap
 * uint32_t    Max bytes allocated since last stats reset
 * uint32_t    TA heap pool byte size
 * uint32_t    Number of failed allocation requests
 * uint32_t    Biggest byte size which allocation failed
 * uint32_t    Biggest byte size which allocation succeeded
 */
#define STATS_CMD_TA_STATS		3

/*
 * STATS_CMD_GET_TIME - Get both REE time and TEE time
 *
 * [out]    value[0].a        REE time as seen by OP-TEE in seconds
 * [out]    value[0].b        REE time as seen by OP-TEE, milliseconds part
 * [out]    value[1].a        TEE system time in seconds
 * [out]    value[1].b        TEE system time, milliseconds part
 */
#define STATS_CMD_GET_TIME		4

#define STATS_NB_POOLS			4

#endif /*__PTA_STATS_H*/
