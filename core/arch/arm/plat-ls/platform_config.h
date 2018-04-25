/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
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

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define STACK_ALIGNMENT			64

#define GIC_BASE			0x01400000
#define GICC_OFFSET			0x2000
#define GICD_OFFSET			0x1000

#define DCFG_BASE			0x01EE0000
#define DCFG_CCSR_BRR			0xE4
#define DCFG_SCRATCHRW1			0x200

#define CSU_BASE			0x01510000
#define CSU_CSL_START			0x0
#define CSU_CSL_END			0xE8
#define CSU_CSL30			0x78
#define CSU_CSL37			0x94

/* Central Security Unit register values */
#define	CSU_ACCESS_ALL			0x00FF00FF
#define	CSU_ACCESS_SEC_ONLY		0x003F003F
#define CSU_SETTING_LOCK		0x01000100

/*  DUART 1 */
#define UART0_BASE			0x021C0500
/*  DUART 2 */
#define UART1_BASE			0x021D0500
/*  LPUART 1 */
#define UART2_BASE			0x02950000
/*  LPUART 2 */
#define UART3_BASE			0x02960000


/* console uart define */
#define CONSOLE_UART_BASE		UART0_BASE

#define DRAM0_BASE			0x80000000

/* Platform specific defines */

#if defined(PLATFORM_FLAVOR_ls1021aqds)
#define DRAM0_SIZE			0x80000000
#define TZDDR_START			0xFC000000
#define TZDDR_SIZE			0x03F00000
#define TEE_RAM_VA_SIZE			(1024 * 1024)
#define TEE_SHMEM_SIZE			(1024 * 1024)
#endif

#if defined(PLATFORM_FLAVOR_ls1021atwr)
#define DRAM0_SIZE			0x40000000
#define TZDDR_START			0xBC000000
#define TZDDR_SIZE			0x03F00000
#define TEE_RAM_VA_SIZE			(1024 * 1024)
#define TEE_SHMEM_SIZE			(1024 * 1024)
#endif

#if defined(PLATFORM_FLAVOR_ls1043ardb) || defined(PLATFORM_FLAVOR_ls1046ardb)
#define DRAM0_SIZE			0x80000000
#define TZDDR_START			0xFC000000
#define TZDDR_SIZE			0x04000000
#define TEE_RAM_VA_SIZE			(2 * 1024 * 1024)
#define TEE_SHMEM_SIZE			(2 * 1024 * 1024)
#endif

#if defined(PLATFORM_FLAVOR_ls1012ardb)
#define DRAM0_SIZE			0x40000000
#define TZDDR_START			0xBC000000
#define TZDDR_SIZE			0x04000000
#define TEE_RAM_VA_SIZE			(2 * 1024 * 1024)
#define TEE_SHMEM_SIZE			(2 * 1024 * 1024)
#endif

/*
 * TEE/TZ RAM layout:
 *
 *  +-----------------------------------------+  <- TZDDR_START
 *  | TEETZ private RAM  |  TEE_RAM           |   ^
 *  |                    +--------------------+   |
 *  |                    |  TA_RAM            |   |
 *  +-----------------------------------------+   | TZDDR_SIZE
 *  |                    |      teecore alloc |   |
 *  |  TEE/TZ and NSec   |  PUB_RAM   --------|   |
 *  |   shared memory    |         NSec alloc |   |
 *  +-----------------------------------------+   v
 *
 *  TEE_RAM : 1MByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

/* define the several memory area sizes */
#if (TZDDR_SIZE < (4 * 1024 * 1024))
#error "Invalid TZDDR_SIZE: at least 4MB expected"
#endif

/* Full GlobalPlatform test suite requires TEE_SHMEM_SIZE to be at least 2MB */
#define TEE_RAM_PH_SIZE			TEE_RAM_VA_SIZE
#define TA_RAM_SIZE			(TZDDR_SIZE - \
					 TEE_RAM_PH_SIZE - TEE_SHMEM_SIZE)

/* define the secure/unsecure memory areas */
#define TZDRAM_BASE			TZDDR_START
#define TZDRAM_SIZE			(TEE_RAM_PH_SIZE + TA_RAM_SIZE)

#define TEE_SHMEM_START			(TZDRAM_BASE + TZDRAM_SIZE)

/* define the memory areas (TEE_RAM must start at reserved DDR start addr */
#define TEE_RAM_START			TZDRAM_BASE
#define TA_RAM_START			(TEE_RAM_START + TEE_RAM_PH_SIZE)

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#endif /*PLATFORM_CONFIG_H*/
