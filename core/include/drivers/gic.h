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

#define GIC_SGI(x)		(x)
#define GIC_PPI(x)		((x) + GIC_PPI_BASE)
#define GIC_SPI(x)		((x) + GIC_SPI_BASE)

struct gic_data {
	vaddr_t gicc_base;
	vaddr_t gicd_base;
	size_t max_it;
	struct itr_chip chip;
};

/*
 * The two gic_init_* functions initializes the struct gic_data which is
 * then used by the other functions.
 */

void gic_init(struct gic_data *gd, paddr_t gicc_base_pa, paddr_t gicd_base_pa);
/* initial base address only */
void gic_init_base_addr(struct gic_data *gd, paddr_t gicc_base_pa,
			paddr_t gicd_base_pa);
/* initial cpu if only, mainly use for secondary cpu setup cpu interface */
void gic_cpu_init(struct gic_data *gd);

void gic_it_handle(struct gic_data *gd);

void gic_dump_state(struct gic_data *gd);
#endif /*__DRIVERS_GIC_H*/
