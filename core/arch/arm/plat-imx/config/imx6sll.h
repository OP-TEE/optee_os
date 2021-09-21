/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */

#ifndef _CONFIG_IMX6SLL_H
#define _CONFIG_IMX6SLL_H

/*
 * PL310 TAG RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:3 - 4 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_TAG_RAM_CTRL_INIT
#define PL310_TAG_RAM_CTRL_INIT		0x00000132
#endif

/*
 * PL310 DATA RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:3 - 4 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_DATA_RAM_CTRL_INIT
#define PL310_DATA_RAM_CTRL_INIT	0x00000132
#endif

/*
 * PL310 Auxiliary Control Register
 *
 * Early BRESP enabled (bit30=1)
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=1)
 * Force write allocated (default) (bit24:23=00)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * 16kb way size (bit19:17=3b001)
 * 16-way associativity (bit16=1)
 * Store buffer device limitation enabled (bit11=0)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) enabled (bit0=1)
 */
#ifndef PL310_AUX_CTRL_INIT
#define PL310_AUX_CTRL_INIT		0x7E430001
#endif

/*
 * PL310 Prefetch Control Register
 *
 * Double linefill enabled (bit30=1)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop disabled (bit24=0)
 * Incr double linefill disable (bit23=0)
 * Prefetch offset = 0xF (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT	0x7000000F

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
#define	SCU_INV_CTRL_INIT		0xFFFFFFFF

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

#endif
