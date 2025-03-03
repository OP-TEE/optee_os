/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Wind River Systems.
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

/*
 * Modified from the Zynq7k platform port.
 */

#include <util.h>

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define STACK_ALIGNMENT			64

/* Snoop Control Unit */
#define SCU_BASE		0xFFFEC000

/* Generic Interrupt Controller */
#define GIC_BASE		SCU_BASE
#define GICC_OFFSET		0x100
#define GICD_OFFSET		0x1000
#define GICC_SIZE		0x100
#define GICD_SIZE		0x1000

/* 0xFFFEC100 */
#define GIC_CPU_BASE		(GIC_BASE + GICC_OFFSET)
/* 0xFFFED000 */
#define GIC_DIST_BASE		(GIC_BASE + GICD_OFFSET)

/* Cache Controller */
#define PL310_BASE		0xFFFEF000
#define PL310_SIZE		0x1000

/* UART Console */
#define UART0_BASE		0xFFC02000
#define UART1_BASE		0xFFC03000

#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_UART_CLK_IN_HZ	100000000
#define CONSOLE_BAUDRATE	115200

/* L3 interconnect */
#define L3REGS_BASE 0xFF800000
#define SECURITY_L4SP_OFFSET 0xC
#define SECURITY_UART0_MASK BIT(6)
#define SECURITY_UART1_MASK BIT(7)
#define ALL_ACCESS_N_BITS(n) \
	((n) > 0 && (n) <= 32 ? GENMASK_32((n) - 1, 0) : 0)

#define TEE_RAM_VA_SIZE			(1024 * 1024)

/*
 * PL310 TAG RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:1 - 2 cycle of read accesses latency
 * bit[2:0]:1 - 2 cycle of setup latency
 */
#ifndef PL310_TAG_RAM_CTRL_INIT
#define PL310_TAG_RAM_CTRL_INIT		0x00000111
#endif

/*
 * PL310 DATA RAM Control Register
 *
 * bit[10:8]:2 - 3 cycle of write accesses latency
 * bit[6:4]:2 - 3 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_DATA_RAM_CTRL_INIT
#define PL310_DATA_RAM_CTRL_INIT	0x00000222
#endif

/*
 * PL310 Auxiliary Control Register
 *
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=0)
 * Force write allocated (default)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * Platform fmavor specific way config:
 * - 64kb way size (bit19:17=3b011)
 * - 8-way associciativity (bit16=0)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#ifndef PL310_AUX_CTRL_INIT
#define PL310_AUX_CTRL_INIT		0x3C460800
#endif

/*
 * PL310 Prefetch Control Register
 *
 * Double linefill disabled (bit30=0)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop enabled (bit24=1)
 * Incr double linefill disable (bit23=0)
 * Prefetch offset = 7 (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT	0x31000007

/*
 * PL310 Power Register
 *
 * Dynamic clock gating enabled
 * Standby mode enabled
 */
#define PL310_POWER_CTRL_INIT		0x00000003

/*
 * SCU Invalidate Register
 *
 * Invalidate all registers
 */
#define SCU_INV_CTRL_INIT		0xFFFFFFFF

/*
 * SCU Access Register
 * - both secure CPU access SCU
 */
#define SCU_SAC_CTRL_INIT		0x0000000F

/*
 * SCU NonSecure Access Register
 * - both nonsec cpu access SCU, private and global timer
 */
#define SCU_NSAC_CTRL_INIT		0x00000FFF

/* all bit enabled in access control register */
#define ACCESS_BITS_ALL			0xFFFFFFFF

/* recommended value for setting the L2C_RAM register */
#define SLCR_L2C_RAM_VALUE		0x00020202

/* place in OCRAM to write secondary entry to */
#define SECONDARY_ENTRY_DROP		0xFFFFFFF0

/* define the memory areas */

#ifdef CFG_WITH_PAGER

/*
 * TEE/TZ RAM layout:
 *
 *  +---------------------------------------+  <- CFG_CORE_TZSRAM_EMUL_START
 *  | TEE private highly | TEE_RAM          |   ^
 *  |   secure memory    |                  |   | CFG_CORE_TZSRAM_EMUL_SIZE
 *  +---------------------------------------+   v
 *
 *  +---------------------------------------+  <- TZDRAM_BASE
 *  | TEE private secure |  TA_RAM          |   ^  + TZDRAM_SIZE
 *  |   external memory  |                  |   v
 *  +---------------------------------------+  <- TEE_SHMEM_START
 *  |     Non secure     |  SHM             |   |
 *  |   shared memory    |                  |   |  + TEE_SHMEM_SIZE
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : default 256kByte
 *  TA_RAM  : all what is left in DDR TEE reserved area
 *  PUB_RAM : default 2MByte
 */

/* emulated SRAM, 256K at start of secure DDR */

#define TZSRAM_BASE			0x3E000000
#define TZSRAM_SIZE			CFG_CORE_TZSRAM_EMUL_SIZE

/* Location of trusted dram */

#define TEE_RAM_START			TZSRAM_BASE
#define TEE_RAM_PH_SIZE			TZSRAM_SIZE

#define TZDRAM_BASE			0x3e100000
#define TZDRAM_SIZE			0x01e00000

#define TEE_SHMEM_START			0x3ff00000
#define TEE_SHMEM_SIZE			0x00100000

#define TA_RAM_START			TZDRAM_BASE
#define TA_RAM_SIZE			TZDRAM_SIZE

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#else /* CFG_WITH_PAGER */

/*
 * TEE/TZ RAM layout:
 *
 *  +---------------------------------------+  <- TZDRAM_BASE
 *  | TEE private secure |  TEE_RAM         |   ^
 *  |   external memory  +------------------+   |
 *  |                    |  TA_RAM          |   |
 *  +---------------------------------------+   | TZDRAM_SIZE
 *  |     Non secure     |  SHM             |   |
 *  |   shared memory    |                  |   |
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : 1MByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

#define TZDRAM_BASE		0x3fd00000
#define TZDRAM_SIZE		(3 * 1024 * 1024)

#define TEE_RAM_START		TZDRAM_BASE
#define TEE_RAM_PH_SIZE		(1 * 1024 * 1024)

#define TA_RAM_START		(TZDRAM_BASE + TEE_RAM_PH_SIZE)
#define TA_RAM_SIZE		(2 * 1024 * 1024)

#define TEE_SHMEM_START		(TZDRAM_BASE + TEE_RAM_PH_SIZE + TA_RAM_SIZE)
#define TEE_SHMEM_SIZE		(1 * 1024 * 1024)

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#endif /* CFG_WITH_PAGER */

#endif /*PLATFORM_CONFIG_H*/
