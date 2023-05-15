// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <config.h>
#include <drivers/gic.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <libfdt.h>
#include <util.h>
#include <io.h>
#include <trace.h>

/* Offsets from gic.gicc_base */
#define GICC_CTLR		(0x000)
#define GICC_PMR		(0x004)
#define GICC_IAR		(0x00C)
#define GICC_EOIR		(0x010)

#define GICC_CTLR_ENABLEGRP0	(1 << 0)
#define GICC_CTLR_ENABLEGRP1	(1 << 1)
#define GICD_CTLR_ENABLEGRP1S	(1 << 2)
#define GICC_CTLR_FIQEN		(1 << 3)

/* Offsets from gic.gicd_base */
#define GICD_CTLR		(0x000)
#define GICD_TYPER		(0x004)
#define GICD_IGROUPR(n)		(0x080 + (n) * 4)
#define GICD_ISENABLER(n)	(0x100 + (n) * 4)
#define GICD_ICENABLER(n)	(0x180 + (n) * 4)
#define GICD_ISPENDR(n)		(0x200 + (n) * 4)
#define GICD_ICPENDR(n)		(0x280 + (n) * 4)
#define GICD_IPRIORITYR(n)	(0x400 + (n) * 4)
#define GICD_ITARGETSR(n)	(0x800 + (n) * 4)
#define GICD_IGROUPMODR(n)	(0xd00 + (n) * 4)
#define GICD_SGIR		(0xF00)

#define GICD_CTLR_ENABLEGRP0	(1 << 0)
#define GICD_CTLR_ENABLEGRP1	(1 << 1)

/* Number of Private Peripheral Interrupt */
#define NUM_PPI	32

/* Number of Software Generated Interrupt */
#define NUM_SGI			16

/* Number of Non-secure Software Generated Interrupt */
#define NUM_NS_SGI		8

/* Number of interrupts in one register */
#define NUM_INTS_PER_REG	32

/* Number of targets in one register */
#define NUM_TARGETS_PER_REG	4

/* Accessors to access ITARGETSRn */
#define ITARGETSR_FIELD_BITS	8
#define ITARGETSR_FIELD_MASK	0xff

/* Maximum number of interrups a GIC can support */
#define GIC_MAX_INTS		1020

#define GICC_IAR_IT_ID_MASK	0x3ff
#define GICC_IAR_CPU_ID_MASK	0x7
#define GICC_IAR_CPU_ID_SHIFT	10

static void gic_op_add(struct itr_chip *chip, size_t it, uint32_t type,
		       uint32_t prio);
static void gic_op_enable(struct itr_chip *chip, size_t it);
static void gic_op_disable(struct itr_chip *chip, size_t it);
static void gic_op_raise_pi(struct itr_chip *chip, size_t it);
static void gic_op_raise_sgi(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask);
static void gic_op_set_affinity(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask);

static const struct itr_ops gic_ops = {
	.add = gic_op_add,
	.enable = gic_op_enable,
	.disable = gic_op_disable,
	.raise_pi = gic_op_raise_pi,
	.raise_sgi = gic_op_raise_sgi,
	.set_affinity = gic_op_set_affinity,
};
DECLARE_KEEP_PAGER(gic_ops);

static size_t probe_max_it(vaddr_t gicc_base __maybe_unused, vaddr_t gicd_base)
{
	int i;
	uint32_t old_ctlr;
	size_t ret = 0;
	const size_t max_regs = ((GIC_MAX_INTS + NUM_INTS_PER_REG - 1) /
					NUM_INTS_PER_REG) - 1;

	/*
	 * Probe which interrupt number is the largest.
	 */
#if defined(CFG_ARM_GICV3)
	old_ctlr = read_icc_ctlr();
	write_icc_ctlr(0);
#else
	old_ctlr = io_read32(gicc_base + GICC_CTLR);
	io_write32(gicc_base + GICC_CTLR, 0);
#endif
	for (i = max_regs; i >= 0; i--) {
		uint32_t old_reg;
		uint32_t reg;
		int b;

		old_reg = io_read32(gicd_base + GICD_ISENABLER(i));
		io_write32(gicd_base + GICD_ISENABLER(i), 0xffffffff);
		reg = io_read32(gicd_base + GICD_ISENABLER(i));
		io_write32(gicd_base + GICD_ICENABLER(i), ~old_reg);
		for (b = NUM_INTS_PER_REG - 1; b >= 0; b--) {
			if (BIT32(b) & reg) {
				ret = i * NUM_INTS_PER_REG + b;
				goto out;
			}
		}
	}
out:
#if defined(CFG_ARM_GICV3)
	write_icc_ctlr(old_ctlr);
#else
	io_write32(gicc_base + GICC_CTLR, old_ctlr);
#endif
	return ret;
}

void gic_cpu_init(struct gic_data *gd)
{
#if defined(CFG_ARM_GICV3)
	assert(gd->gicd_base);
#else
	assert(gd->gicd_base && gd->gicc_base);
#endif

	/* per-CPU interrupts config:
	 * ID0-ID7(SGI)   for Non-secure interrupts
	 * ID8-ID15(SGI)  for Secure interrupts.
	 * All PPI config as Non-secure interrupts.
	 */
	io_write32(gd->gicd_base + GICD_IGROUPR(0), 0xffff00ff);

	/* Set the priority mask to permit Non-secure interrupts, and to
	 * allow the Non-secure world to adjust the priority mask itself
	 */
#if defined(CFG_ARM_GICV3)
	write_icc_pmr(0x80);
	write_icc_igrpen1(1);
#else
	io_write32(gd->gicc_base + GICC_PMR, 0x80);

	/* Enable GIC */
	io_write32(gd->gicc_base + GICC_CTLR,
		   GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 |
		   GICC_CTLR_FIQEN);
#endif
}

void gic_init(struct gic_data *gd, paddr_t gicc_base_pa, paddr_t gicd_base_pa)
{
	size_t n;

	gic_init_base_addr(gd, gicc_base_pa, gicd_base_pa);

	for (n = 0; n <= gd->max_it / NUM_INTS_PER_REG; n++) {
		/* Disable interrupts */
		io_write32(gd->gicd_base + GICD_ICENABLER(n), 0xffffffff);

		/* Make interrupts non-pending */
		io_write32(gd->gicd_base + GICD_ICPENDR(n), 0xffffffff);

		/* Mark interrupts non-secure */
		if (n == 0) {
			/* per-CPU inerrupts config:
			 * ID0-ID7(SGI)	  for Non-secure interrupts
			 * ID8-ID15(SGI)  for Secure interrupts.
			 * All PPI config as Non-secure interrupts.
			 */
			io_write32(gd->gicd_base + GICD_IGROUPR(n), 0xffff00ff);
		} else {
			io_write32(gd->gicd_base + GICD_IGROUPR(n), 0xffffffff);
		}
	}

	/* Set the priority mask to permit Non-secure interrupts, and to
	 * allow the Non-secure world to adjust the priority mask itself
	 */
#if defined(CFG_ARM_GICV3)
	write_icc_pmr(0x80);
	write_icc_igrpen1(1);
	io_setbits32(gd->gicd_base + GICD_CTLR, GICD_CTLR_ENABLEGRP1S);
#else
	io_write32(gd->gicc_base + GICC_PMR, 0x80);

	/* Enable GIC */
	io_write32(gd->gicc_base + GICC_CTLR, GICC_CTLR_FIQEN |
		   GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1);
	io_setbits32(gd->gicd_base + GICD_CTLR,
		     GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1);
#endif
}

static int gic_dt_get_irq(const uint32_t *properties, int count, uint32_t *type,
			  uint32_t *prio)
{
	int it_num = DT_INFO_INVALID_INTERRUPT;

	if (type)
		*type = IRQ_TYPE_NONE;

	if (prio)
		*prio = 0;

	if (!properties || count < 2)
		return DT_INFO_INVALID_INTERRUPT;

	it_num = fdt32_to_cpu(properties[1]);

	switch (fdt32_to_cpu(properties[0])) {
	case 1:
		it_num += 16;
		break;
	case 0:
		it_num += 32;
		break;
	default:
		it_num = DT_INFO_INVALID_INTERRUPT;
	}

	return it_num;
}

void gic_init_base_addr(struct gic_data *gd,
			paddr_t gicc_base_pa __maybe_unused,
			paddr_t gicd_base_pa)
{
	vaddr_t gicc_base = 0;
	vaddr_t gicd_base = 0;

	assert(cpu_mmu_enabled());

	gicd_base = core_mmu_get_va(gicd_base_pa, MEM_AREA_IO_SEC,
				    GIC_DIST_REG_SIZE);
	if (!gicd_base)
		panic();

	if (!IS_ENABLED(CFG_ARM_GICV3)) {
		gicc_base = core_mmu_get_va(gicc_base_pa, MEM_AREA_IO_SEC,
					    GIC_CPU_REG_SIZE);
		if (!gicc_base)
			panic();
	}

	gd->gicc_base = gicc_base;
	gd->gicd_base = gicd_base;
	gd->max_it = probe_max_it(gicc_base, gicd_base);
	gd->chip.ops = &gic_ops;

	if (IS_ENABLED(CFG_DT))
		gd->chip.dt_get_irq = gic_dt_get_irq;
}

static void gic_it_add(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Disable the interrupt */
	io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
	/* Make it non-pending */
	io_write32(gd->gicd_base + GICD_ICPENDR(idx), mask);
	/* Assign it to group0 */
	io_clrbits32(gd->gicd_base + GICD_IGROUPR(idx), mask);
#if defined(CFG_ARM_GICV3)
	/* Assign it to group1S */
	io_setbits32(gd->gicd_base + GICD_IGROUPMODR(idx), mask);
#endif
}

static void gic_it_set_cpu_mask(struct gic_data *gd, size_t it,
				uint8_t cpu_mask)
{
	size_t idx __maybe_unused = it / NUM_INTS_PER_REG;
	uint32_t mask __maybe_unused = 1 << (it % NUM_INTS_PER_REG);
	uint32_t target, target_shift;
	vaddr_t itargetsr = gd->gicd_base +
			    GICD_ITARGETSR(it / NUM_TARGETS_PER_REG);

	/* Assigned to group0 */
	assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Route it to selected CPUs */
	target = io_read32(itargetsr);
	target_shift = (it % NUM_TARGETS_PER_REG) * ITARGETSR_FIELD_BITS;
	target &= ~(ITARGETSR_FIELD_MASK << target_shift);
	target |= cpu_mask << target_shift;
	DMSG("cpu_mask: writing 0x%x to 0x%" PRIxVA, target, itargetsr);
	io_write32(itargetsr, target);
	DMSG("cpu_mask: 0x%x", io_read32(itargetsr));
}

static void gic_it_set_prio(struct gic_data *gd, size_t it, uint8_t prio)
{
	size_t idx __maybe_unused = it / NUM_INTS_PER_REG;
	uint32_t mask __maybe_unused = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Set prio it to selected CPUs */
	DMSG("prio: writing 0x%x to 0x%" PRIxVA,
		prio, gd->gicd_base + GICD_IPRIORITYR(0) + it);
	io_write8(gd->gicd_base + GICD_IPRIORITYR(0) + it, prio);
}

static void gic_it_enable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	vaddr_t base = gd->gicd_base;

	/* Assigned to group0 */
	assert(!(io_read32(base + GICD_IGROUPR(idx)) & mask));

	/* Enable the interrupt */
	io_write32(base + GICD_ISENABLER(idx), mask);
}

static void gic_it_disable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Disable the interrupt */
	io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
}

static void gic_it_set_pending(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = BIT32(it % NUM_INTS_PER_REG);

	/* Should be Peripheral Interrupt */
	assert(it >= NUM_SGI);

	/* Raise the interrupt */
	io_write32(gd->gicd_base + GICD_ISPENDR(idx), mask);
}

static void gic_it_raise_sgi(struct gic_data *gd, size_t it,
		uint8_t cpu_mask, uint8_t group)
{
	uint32_t mask_id = it & 0xf;
	uint32_t mask_group = group & 0x1;
	uint32_t mask_cpu = cpu_mask & 0xff;
	uint32_t mask = (mask_id | SHIFT_U32(mask_group, 15) |
		SHIFT_U32(mask_cpu, 16));

	/* Should be Software Generated Interrupt */
	assert(it < NUM_SGI);

	/* Raise the interrupt */
	io_write32(gd->gicd_base + GICD_SGIR, mask);
}

static uint32_t gic_read_iar(struct gic_data *gd __maybe_unused)
{
#if defined(CFG_ARM_GICV3)
	return read_icc_iar1();
#else
	return io_read32(gd->gicc_base + GICC_IAR);
#endif
}

static void gic_write_eoir(struct gic_data *gd __maybe_unused, uint32_t eoir)
{
#if defined(CFG_ARM_GICV3)
	write_icc_eoir1(eoir);
#else
	io_write32(gd->gicc_base + GICC_EOIR, eoir);
#endif
}

static bool gic_it_is_enabled(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(io_read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask);
}

static bool __maybe_unused gic_it_get_group(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask);
}

static uint32_t __maybe_unused gic_it_get_target(struct gic_data *gd, size_t it)
{
	size_t reg_idx = it / NUM_TARGETS_PER_REG;
	uint32_t target_shift = (it % NUM_TARGETS_PER_REG) *
				ITARGETSR_FIELD_BITS;
	uint32_t target_mask = ITARGETSR_FIELD_MASK << target_shift;
	uint32_t target = io_read32(gd->gicd_base + GICD_ITARGETSR(reg_idx));

	return (target & target_mask) >> target_shift;
}

void gic_dump_state(struct gic_data *gd)
{
	int i;

#if defined(CFG_ARM_GICV3)
	DMSG("GICC_CTLR: 0x%x", read_icc_ctlr());
#else
	DMSG("GICC_CTLR: 0x%x", io_read32(gd->gicc_base + GICC_CTLR));
#endif
	DMSG("GICD_CTLR: 0x%x", io_read32(gd->gicd_base + GICD_CTLR));

	for (i = 0; i <= (int)gd->max_it; i++) {
		if (gic_it_is_enabled(gd, i)) {
			DMSG("irq%d: enabled, group:%d, target:%x", i,
			     gic_it_get_group(gd, i), gic_it_get_target(gd, i));
		}
	}
}

void gic_it_handle(struct gic_data *gd)
{
	uint32_t iar;
	uint32_t id;

	iar = gic_read_iar(gd);
	id = iar & GICC_IAR_IT_ID_MASK;

	if (id <= gd->max_it)
		itr_handle(id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);

	gic_write_eoir(gd, iar);
}

static void gic_op_add(struct itr_chip *chip, size_t it,
		       uint32_t type __unused,
		       uint32_t prio __unused)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it > gd->max_it)
		panic();

	gic_it_add(gd, it);
	/* Set the CPU mask to deliver interrupts to any online core */
	gic_it_set_cpu_mask(gd, it, 0xff);
	gic_it_set_prio(gd, it, 0x1);
}

static void gic_op_enable(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it > gd->max_it)
		panic();

	gic_it_enable(gd, it);
}

static void gic_op_disable(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it > gd->max_it)
		panic();

	gic_it_disable(gd, it);
}

static void gic_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it > gd->max_it)
		panic();

	gic_it_set_pending(gd, it);
}

static void gic_op_raise_sgi(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it > gd->max_it)
		panic();

	if (it < NUM_NS_SGI)
		gic_it_raise_sgi(gd, it, cpu_mask, 1);
	else
		gic_it_raise_sgi(gd, it, cpu_mask, 0);
}
static void gic_op_set_affinity(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it > gd->max_it)
		panic();

	gic_it_set_cpu_mask(gd, it, cpu_mask);
}
