/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2016, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <util.h>
#include <mm/generic_ram_layout.h>

/* Below are platform/SoC settings specific to stm platform flavors */

#if defined(PLATFORM_FLAVOR_b2260)

#define CPU_IOMEM_BASE		0x08760000
#define CPU_IOMEM_SIZE		0x000a0000
#define CPU_PORT_FILT_START	0x40000000
#define CPU_PORT_FILT_END	0xC0000000
#define STXHXXX_LPM_PERIPH_BASE	0x09700000
#define RNG_BASE		0x08A89000
#define RNG_SIZE		0x00001000

#define ASC_NUM			21
#define UART_CONSOLE_BASE	ST_ASC21_REGS_BASE

#elif defined(PLATFORM_FLAVOR_cannes)

#define CPU_IOMEM_BASE		0x08760000
#define CPU_IOMEM_SIZE		0x000a0000
#define CPU_PORT_FILT_START	0x40000000
#define CPU_PORT_FILT_END	0xC0000000
#define STXHXXX_LPM_PERIPH_BASE	0x09400000
#define RNG_BASE		0x08A89000
#define RNG_SIZE		0x00001000

#define ASC_NUM			20
#define UART_CONSOLE_BASE	ST_ASC20_REGS_BASE

#else /* defined(PLATFORM_FLAVOR_xxx) */

#error "Unknown platform flavor"

#endif /* defined(PLATFORM_FLAVOR_xxx) */

#define PL310_BASE		(CPU_IOMEM_BASE + 0x2000)
#define GIC_DIST_BASE		(CPU_IOMEM_BASE + 0x1000)
#define SCU_BASE		(CPU_IOMEM_BASE + 0x0000)
#define GIC_CPU_BASE		(CPU_IOMEM_BASE + 0x0100)
#define ST_ASC20_REGS_BASE	(STXHXXX_LPM_PERIPH_BASE + 0x00130000)
#define ST_ASC21_REGS_BASE	(STXHXXX_LPM_PERIPH_BASE + 0x00131000)

/* Below are settings common to stm platform flavors */

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		32

/*
 * CP15 Secure ConTroL Register (SCTLR
 *
 * - Round-Robin replac. for icache, btac, i/duTLB (bit14: RoundRobin)
 */
#define CPU_SCTLR_INIT			0x00004000

/*
 * CP15 Auxiliary ConTroL Register (ACTRL)
 *
 * - core always in full SMP (FW bit0=1, SMP bit6=1)
 * - L2 write full line of zero disabled (bit3=0)
 *   (keep WFLZ low. Will be set once outer L2 is ready)
 */
#define CPU_ACTLR_INIT			0x00000041

/*
 * CP15 NonSecure Access Control Register (NSACR)
 *
 * - NSec cannot change ACTRL.SMP (NS_SMP bit18=0)
 * - Nsec can lockdown TLB (TL bit17=1)
 * - NSec cannot access PLE (PLE bit16=0)
 * - NSec can use SIMD/VFP (CP10/CP11) (bit15:14=2b00, bit11:10=2b11)
 */
#define CPU_NSACR_INIT			0x00020C00

/*
 * CP15 Power Control Register (PCR)
 *
 * - no change latency, enable clk gating
 */
#define CPU_PCR_INIT			0x00000001


/*
 * SCU Secure Access Control / NonSecure Access Control
 *
 * SAC:  Both secure CPU access SCU (bit[3:0]).
 * NSAC: Both nonsec cpu access SCU (bit[3:0]), private timers (bit[7:4])
 *       and global timers (bit[11:8]).
 */
#if !defined(SCU_SAC_INIT) || !defined(SCU_NSAC_INIT)
#define SCU_CPUS_MASK		(SHIFT_U32(1, CFG_TEE_CORE_NB_CORE) - 1)

#define SCU_SAC_INIT	SCU_CPUS_MASK
#define SCU_NSAC_INIT	(SHIFT_U32(SCU_CPUS_MASK, SCU_NSAC_SCU_SHIFT) | \
			SHIFT_U32(SCU_CPUS_MASK, SCU_NSAC_PTIMER_SHIFT) | \
			SHIFT_U32(SCU_CPUS_MASK, SCU_NSAC_GTIMER_SHIFT))
#endif

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
 * - way size (bit19:17)
 * - way associciativity (bit16)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#ifndef PL310_AUX_CTRL_INIT
#define PL310_AUX_CTRL_INIT		0x3C480800
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
 * SCU Control Register : CTRL = 0x00000065
 * - ic stanby enable=1
 * - scu standby enable=1
 * - scu enable=1
 */
#define SCU_CTRL_INIT			0x00000065

/*
 * Register non-secure DDR chunks for dynamic shared memory: these are
 * DDR ranges that do not include OP-TEE secure memory.
 * Some Stm platforms may reserve beginning of the DDR for non REE memory.
 */

#ifdef CFG_DDR_START
/* Carvout out secure RAM range (emulated SRAM is expected near DRAM) */
#if defined(CFG_WITH_PAGER) && defined(TZSRAM_BASE)
#if TZSRAM_BASE >= CFG_DDR_START
#define STM_SECDDR_BASE		MIN_UNSAFE(TZSRAM_BASE, TZDRAM_BASE)
#define STM_SECDDR_END		MAX_UNSAFE(TZSRAM_BASE + TZSRAM_SIZE, \
					   TZDRAM_BASE + TZDRAM_SIZE)
#endif /*TZSRAM_BASE >= CFG_DDR_START*/
#endif /*CFG_WITH_PAGER && TZSRAM_BASE*/

#ifndef STM_SECDDR_BASE
#define STM_SECDDR_BASE		TZDRAM_BASE
#define STM_SECDDR_END		(TZDRAM_BASE + TZDRAM_SIZE)
#endif

#define STM_SECDDR_SIZE		(STM_SECDDR_END - STM_SECDDR_BASE)
/* Register the DDR chunks that do not intersect the secure DDR single area */
#define DRAM0_BASE		(CFG_DDR_START + CFG_STM_RSV_DRAM_STARTBYTES)
#define DRAM0_SIZE		(STM_SECDDR_BASE - DRAM0_BASE)
#if (STM_SECDDR_END < 0x80000000ULL)
#define DRAM1_BASE		STM_SECDDR_END
#define DRAM1_SIZE		((CFG_DDR_START - DRAM1_BASE) + CFG_DDR_SIZE)
#endif
#endif /*CFG_DDR_START*/

#endif /* PLATFORM_CONFIG_H */
