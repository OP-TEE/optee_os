/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2016, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

/* Below are platform/SoC settings specific to stm platform flavors */

#if defined(PLATFORM_FLAVOR_b2260)

#ifdef CFG_DDR_SECURE_BASE
/* Non-secure external RAM: DDR eventually split in 2 by TZ reserved DDR */
#define DRAM0_BASE		CFG_DDR_START
#define DRAM0_SIZE		(CFG_DDR_SECURE_BASE - CFG_DDR_START)
#if ((CFG_DDR_SECURE_BASE + CFG_DDR_SECURE_SIZE) < 0x80000000ULL)
#define DRAM1_BASE		(CFG_DDR_SECURE_BASE + CFG_DDR_SECURE_SIZE)
#define DRAM1_SIZE		((CFG_DDR_START - DRAM1_BASE) + CFG_DDR_SIZE)
#endif
#endif

/* IOmem */
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

#ifdef CFG_DDR_SECURE_BASE
/*
 * Non-secure external RAM: DDR eventually split in 2 by TZ reserved DDR.
 * The 32 first MBytes of the DDR are not eligible to REE/TEE SHM.
 */
#define DRAM0_BASE		(CFG_DDR_START + 0x02000000)
#define DRAM0_SIZE		(CFG_DDR_SECURE_BASE - CFG_DDR_START)
#if ((CFG_DDR_SECURE_BASE + CFG_DDR_SECURE_SIZE) < 0x80000000ULL)
#define DRAM1_BASE		(CFG_DDR_SECURE_BASE + CFG_DDR_SECURE_SIZE)
#define DRAM1_SIZE		(CFG_DDR_START + CFG_DDR_SIZE - DRAM1_BASE)
#endif
#endif

/* IOmem */
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

/* Below are settings common to stm platform flavors */

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
 * TEE RAM layout without CFG_WITH_PAGER:
 *
 *  +---------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEE private secure |  TEE_RAM         |   ^
 *  |   external memory  +------------------+   |
 *  |                    |  TA_RAM          |   |
 *  +---------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  | Secure Data Path test memory (opt.)   |   |
 *  +---------------------------------------+   |
 *  |     Non secure     |  SHM             |   |
 *  |   shared memory    |                  |   |
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : default 1MByte
 *  TA_RAM  : all what is left
 *  SDP_RAM : optional default SDP test memory 8MByte
 *  PUB_RAM : default 2MByte
 *
 * ----------------------------------------------------------------------------
 * TEE RAM layout with CFG_WITH_PAGER=y:
 *
 *  +---------------------------------------+  <- CFG_CORE_TZSRAM_EMUL_START
 *  | TEE private highly | TEE_RAM          |   ^
 *  |   secure memory    |                  |   | CFG_CORE_TZSRAM_EMUL_SIZE
 *  +---------------------------------------+   v
 *
 *  +---------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEE private secure |  TA_RAM          |   ^
 *  |   external memory  |                  |   |
 *  +---------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  | Secure Data Path test memory (opt.)   |   |
 *  +---------------------------------------+   |
 *  |     Non secure     |  SHM             |   |
 *  |   shared memory    |                  |   |
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : default 256kByte
 *  TA_RAM  : all what is left in DDR TEE reserved area
 *  SDP_RAM : optional default SDP test memory 8MByte
 *  PUB_RAM : default 2MByte
 */

/* default locate shared memory at the end of the TEE reserved DDR */
#ifdef CFG_SHMEM_SIZE
#define TEE_SHMEM_SIZE		CFG_SHMEM_SIZE
#else
#define TEE_SHMEM_SIZE		(2 * 1024 * 1024)
#endif

#ifdef CFG_SHMEM_START
#define TEE_SHMEM_START		CFG_SHMEM_START
#else
#define TEE_SHMEM_START		(CFG_DDR_TEETZ_RESERVED_START + \
					CFG_DDR_TEETZ_RESERVED_SIZE - \
					TEE_SHMEM_SIZE)
#endif

/*
 * Secure data path test memory pool
 * - If no SDP, no SDP test memory.
 * - Can be provided by configuration directives CFG_TEE_SDP_MEM_BASE
 *   and CFG_TEE_SDP_MEM_TEST_SIZE.
 * - If only the size is defined by CFG_TEE_SDP_MEM_TEST_SIZE, default
 *   locate a SDP test memory and the end of the TA RAM.
 */
#if defined(CFG_SECURE_DATA_PATH) && !defined(CFG_TEE_SDP_MEM_BASE)
#if defined(CFG_TEE_SDP_MEM_TEST_SIZE)
#define TEE_SDP_TEST_MEM_SIZE	CFG_TEE_SDP_MEM_TEST_SIZE
#else
#define TEE_SDP_TEST_MEM_SIZE	0x00300000
#endif
#define TEE_SDP_TEST_MEM_BASE	(CFG_DDR_TEETZ_RESERVED_START + \
					CFG_DDR_TEETZ_RESERVED_SIZE - \
					TEE_SHMEM_SIZE - TEE_SDP_TEST_MEM_SIZE)
#endif
#ifndef TEE_SDP_TEST_MEM_SIZE
#define TEE_SDP_TEST_MEM_SIZE	0
#endif

#if defined(CFG_WITH_PAGER)

#define TZSRAM_BASE		CFG_CORE_TZSRAM_EMUL_START
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		CFG_DDR_TEETZ_RESERVED_START
#define TZDRAM_SIZE		(CFG_DDR_TEETZ_RESERVED_SIZE - \
					TEE_SHMEM_SIZE - \
					TEE_SDP_TEST_MEM_SIZE)

#define TEE_RAM_START		TZSRAM_BASE
#define TEE_RAM_PH_SIZE		TZSRAM_SIZE

#define TA_RAM_START		TZDRAM_BASE
#define TA_RAM_SIZE		TZDRAM_SIZE

#else  /* CFG_WITH_PAGER */

#define TZDRAM_BASE		CFG_DDR_TEETZ_RESERVED_START
#define TZDRAM_SIZE		(CFG_DDR_TEETZ_RESERVED_SIZE - \
					TEE_SHMEM_SIZE - \
					TEE_SDP_TEST_MEM_SIZE)

#define TEE_RAM_START		TZDRAM_BASE
#define TEE_RAM_PH_SIZE		(1 * 1024 * 1024)

#define TA_RAM_START		(TZDRAM_BASE + TEE_RAM_PH_SIZE)
#define TA_RAM_SIZE		(TZDRAM_SIZE - TEE_RAM_PH_SIZE)

#endif /* !CFG_WITH_PAGER */

#define TEE_RAM_VA_SIZE		(1024 * 1024)

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#define PL310_BASE		(CPU_IOMEM_BASE + 0x2000)
#define GIC_DIST_BASE		(CPU_IOMEM_BASE + 0x1000)
#define SCU_BASE		(CPU_IOMEM_BASE + 0x0000)
#define GIC_CPU_BASE		(CPU_IOMEM_BASE + 0x0100)
#define ST_ASC20_REGS_BASE	(STXHXXX_LPM_PERIPH_BASE + 0x00130000)
#define ST_ASC21_REGS_BASE	(STXHXXX_LPM_PERIPH_BASE + 0x00131000)

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		32

#endif /* PLATFORM_CONFIG_H */
