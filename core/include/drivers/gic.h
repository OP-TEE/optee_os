/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2026 Arm Limited
 */

#ifndef __DRIVERS_GIC_H
#define __DRIVERS_GIC_H
#include <types_ext.h>
#include <kernel/interrupt.h>

#ifdef _CFG_ARM_V3_OR_V4
#define GICD_FRAME_SIZE         (64 * 1024)
#define GICC_FRAME_SIZE         (64 * 1024)
#define GICR_FRAME_SIZE         (64 * 1024)
#else /* GICv2 and earlier */
#define GICD_FRAME_SIZE         (4 * 1024)
#define GICC_FRAME_SIZE         (4 * 1024)
#define GICR_FRAME_SIZE         0 /* Unsupported */
#endif

#define GIC_CPU_REG_SIZE        GICC_FRAME_SIZE
#define GIC_DIST_REG_SIZE       GICD_FRAME_SIZE
#ifdef _CFG_ARM_V3_OR_V4
/*
 * The frames for each Redistributor are contiguous and are ordered as
 * follows:
 * 1. RD_base
 * 2. SGI_base
 *
 * In GICv4, there are two additional 64KB frames:
 * - A frame to control virtual LPIs. The base address of this frame is
 *   referred to as VLPI_base.
 * - A reserved frame.
 *
 * The frames for each Redistributor are contiguous and are
 * ordered as follows:
 *   1. RD_base
 *   2. SGI_base
 *   3. VLPI_base
 *   4. Reserved
 */
#ifdef CFG_ARM_GICV4
#define GICR_FRAME_COUNT        4
#else /* CFG_ARM_GICV3 */
#define GICR_FRAME_COUNT        2
#endif
#define GIC_REDIST_REG_SIZE     (GICR_FRAME_COUNT * GICR_FRAME_SIZE)
#else /* GICv2 and earlier */
#define GIC_REDIST_REG_SIZE     0 /* Unsupported */
#endif

#define GIC_PPI_BASE		U(16)
#define GIC_SPI_BASE		U(32)

#define GIC_SGI_TO_ITNUM(x)	(x)
#define GIC_PPI_TO_ITNUM(x)	((x) + GIC_PPI_BASE)
#define GIC_SPI_TO_ITNUM(x)	((x) + GIC_SPI_BASE)

/*
 * Default lowest ID for secure SGIs, note that this does not account for
 * interrupts donated to non-secure world with gic_init_donate_sgi_to_ns().
 */
#define GIC_SGI_SEC_BASE	8
/* Max ID for secure SGIs */
#define GIC_SGI_SEC_MAX		15
/* Default IRQ priority for SPIs in Non-Sec EL1 */
#define GIC_SPI_PRI_NS_EL1	0x50

/*
 * The two gic_init() and gic_init_v3() functions initializes the struct
 * gic_data which is then used by the other functions. These two functions
 * also initializes the GIC and are only supposed to be called from the
 * primary boot CPU.
 */
void gic_init_v3(paddr_t gicc_base_pa, paddr_t gicd_base_pa,
		 paddr_t gicr_base_pa);
static inline void gic_init(paddr_t gicc_base_pa, paddr_t gicd_base_pa)
{
	gic_init_v3(gicc_base_pa, gicd_base_pa, 0);
}

/* Donates one of the secure SGIs to normal world */
void gic_init_donate_sgi_to_ns(size_t it);

/*
 * Does per-CPU specific GIC initialization, should be called by all
 * secondary CPUs when booting.
 */
void gic_init_per_cpu(void);

/* Print GIC state to console */
void gic_dump_state(void);

/*
 * Reassign one of the SPIs to normal world and set its priority to
 * GIC_SPI_PRI_NS_EL1. Ensure that the interrupt is currently
 * assigned to secure world and disabled when this function is called.
 */
TEE_Result gic_spi_release_to_ns(size_t it);
#endif /*__DRIVERS_GIC_H*/
