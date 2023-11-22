/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __DRIVERS_GIC_H
#define __DRIVERS_GIC_H
#include <types_ext.h>
#include <kernel/interrupt.h>

#if defined(CFG_ARM_GICV3)
#define GIC_DIST_REG_SIZE	0x10000
#define GIC_CPU_REG_SIZE	0x10000
#else
#define GIC_DIST_REG_SIZE	0x1000
#define GIC_CPU_REG_SIZE	0x1000
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
#endif /*__DRIVERS_GIC_H*/
