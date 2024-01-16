/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, STMicroelectronics
 * Copyright (C) 2022, Microchip
 */
#ifndef __PTA_STATS_H
#define __PTA_STATS_H

#include <stdint.h>
#include <tee_api_types.h>

#define STATS_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

/*
 * STATS_CMD_PAGER_STATS - Get statistics on pager
 *
 * [out]    value[0].a        Number of unlocked pages
 * [out]    value[0].b        Page pool size
 * [out]    value[1].a        R/O faults since last stats dump
 * [out]    value[1].b        R/W faults since last stats dump
 * [out]    value[2].a        Hidden faults since last stats dump
 * [out]    value[2].b        Zi pages released since last stats dump
 */
#define STATS_CMD_PAGER_STATS		0

/*
 * STATS_CMD_ALLOC_STATS - Get statistics on core heap allocations
 *
 * [in]     value[0].a       ID of allocator(s) to get stats from (ALLOC_ID_*)
 * [out]    memref[0]        Array of struct pta_stats_alloc instances
 */
#define STATS_CMD_ALLOC_STATS		1

#define ALLOC_ID_ALL		0	/* All allocators */
#define ALLOC_ID_HEAP		1	/* Core heap allocator */
#define ALLOC_ID_PUBLIC_DDR	2	/* Public DDR allocator (deprecated) */
#define ALLOC_ID_TA_RAM		3	/* TA_RAM allocator */
#define ALLOC_ID_NEXUS_HEAP	4	/* Nexus heap allocator */
#define STATS_NB_POOLS		5

#define TEE_ALLOCATOR_DESC_LENGTH 32

struct pta_stats_alloc {
	char desc[TEE_ALLOCATOR_DESC_LENGTH];
	uint32_t allocated;               /* Bytes currently allocated */
	uint32_t max_allocated;           /* Tracks max value of allocated */
	uint32_t size;                    /* Total size for this allocator */
	uint32_t num_alloc_fail;          /* Number of failed alloc requests */
	uint32_t biggest_alloc_fail;      /* Size of biggest failed alloc */
	uint32_t biggest_alloc_fail_used; /* Alloc bytes when above occurred */
};

/*
 * STATS_CMD_MEMLEAK_STATS - Print memory leakage info to console
 */
#define STATS_CMD_MEMLEAK_STATS		2

/*
 * STATS_CMD_TA_STATS - Get information on TA instances
 *
 * [out]    memref[0]        Array of struct pta_stats_ta per loaded TA
 */
#define STATS_CMD_TA_STATS		3

struct pta_stats_ta {
	TEE_UUID uuid;
	uint32_t panicked;	/* True if TA has panicked */
	uint32_t sess_num;	/* Number of opened session */
	struct pta_stats_alloc heap;
};

/*
 * STATS_CMD_GET_TIME - Get both REE time and TEE time
 *
 * [out]    value[0].a        REE time as seen by OP-TEE in seconds
 * [out]    value[0].b        REE time as seen by OP-TEE, milliseconds part
 * [out]    value[1].a        TEE system time in seconds
 * [out]    value[1].b        TEE system time, milliseconds part
 */
#define STATS_CMD_GET_TIME		4

/*
 * STATS_CMD_PRINT_DRIVER_INFO - Print device drivers information to console
 *
 * [in]    value[0].a        Target driver, one of STATS_DRIVER_TYPE_*
 */
#define STATS_CMD_PRINT_DRIVER_INFO	5

#define STATS_DRIVER_TYPE_CLOCK		0
#define STATS_DRIVER_TYPE_REGULATOR	1

#endif /*__PTA_STATS_H*/
