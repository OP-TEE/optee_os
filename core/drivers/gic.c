/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <assert.h>
#include <drivers/gic.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
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

#define GIC_SPURIOUS_ID		1023

#define GICC_IAR_IT_ID_MASK	0x3ff
#define GICC_IAR_CPU_ID_MASK	0x7
#define GICC_IAR_CPU_ID_SHIFT	10

static void gic_op_add(struct itr_chip *chip, size_t it, uint32_t flags);
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

static size_t probe_max_it(vaddr_t gicc_base, vaddr_t gicd_base)
{
	int i;
	uint32_t old_ctlr;
	size_t ret = 0;
	const size_t max_regs = ((GIC_MAX_INTS + NUM_INTS_PER_REG - 1) /
					NUM_INTS_PER_REG) - 1;

	/*
	 * Probe which interrupt number is the largest.
	 */
	old_ctlr = read32(gicc_base + GICC_CTLR);
	write32(0, gicc_base + GICC_CTLR);
	for (i = max_regs; i >= 0; i--) {
		uint32_t old_reg;
		uint32_t reg;
		int b;

		old_reg = read32(gicd_base + GICD_ISENABLER(i));
		write32(0xffffffff, gicd_base + GICD_ISENABLER(i));
		reg = read32(gicd_base + GICD_ISENABLER(i));
		write32(old_reg, gicd_base + GICD_ICENABLER(i));
		for (b = NUM_INTS_PER_REG - 1; b >= 0; b--) {
			if (BIT32(b) & reg) {
				ret = i * NUM_INTS_PER_REG + b;
				goto out;
			}
		}
	}
out:
	write32(old_ctlr, gicc_base + GICC_CTLR);
	return ret;
}

void gic_cpu_init(struct gic_data *gd)
{
	assert(gd->gicd_base && gd->gicc_base);

	/* per-CPU interrupts config:
	 * ID0-ID7(SGI)   for Non-secure interrupts
	 * ID8-ID15(SGI)  for Secure interrupts.
	 * All PPI config as Non-secure interrupts.
	 */
	write32(0xffff00ff, gd->gicd_base + GICD_IGROUPR(0));

	/* Set the priority mask to permit Non-secure interrupts, and to
	 * allow the Non-secure world to adjust the priority mask itself
	 */
	write32(0x80, gd->gicc_base + GICC_PMR);

	/* Enable GIC */
	write32(GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN,
		gd->gicc_base + GICC_CTLR);
}

void gic_init(struct gic_data *gd, vaddr_t gicc_base, vaddr_t gicd_base)
{
	size_t n;

	gic_init_base_addr(gd, gicc_base, gicd_base);

	for (n = 0; n <= gd->max_it / NUM_INTS_PER_REG; n++) {
		/* Disable interrupts */
		write32(0xffffffff, gd->gicd_base + GICD_ICENABLER(n));

		/* Make interrupts non-pending */
		write32(0xffffffff, gd->gicd_base + GICD_ICPENDR(n));

		/* Mark interrupts non-secure */
		if (n == 0) {
			/* per-CPU inerrupts config:
                         * ID0-ID7(SGI)   for Non-secure interrupts
                         * ID8-ID15(SGI)  for Secure interrupts.
                         * All PPI config as Non-secure interrupts.
			 */
			write32(0xffff00ff, gd->gicd_base + GICD_IGROUPR(n));
		} else {
			write32(0xffffffff, gd->gicd_base + GICD_IGROUPR(n));
		}
	}

	/* Set the priority mask to permit Non-secure interrupts, and to
	 * allow the Non-secure world to adjust the priority mask itself
	 */
	write32(0x80, gd->gicc_base + GICC_PMR);

	/* Enable GIC */
	write32(GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN,
		gd->gicc_base + GICC_CTLR);
	write32(GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1,
		gd->gicd_base + GICD_CTLR);
}

void gic_init_base_addr(struct gic_data *gd, vaddr_t gicc_base,
			vaddr_t gicd_base)
{
	gd->gicc_base = gicc_base;
	gd->gicd_base = gicd_base;
	gd->max_it = probe_max_it(gicc_base, gicd_base);
	gd->chip.ops = &gic_ops;
}

static void gic_it_add(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Disable the interrupt */
	write32(mask, gd->gicd_base + GICD_ICENABLER(idx));
	/* Make it non-pending */
	write32(mask, gd->gicd_base + GICD_ICPENDR(idx));
	/* Assign it to group0 */
	write32(read32(gd->gicd_base + GICD_IGROUPR(idx)) & ~mask,
			gd->gicd_base + GICD_IGROUPR(idx));
}

static void gic_it_set_cpu_mask(struct gic_data *gd, size_t it,
				uint8_t cpu_mask)
{
	size_t idx __maybe_unused = it / NUM_INTS_PER_REG;
	uint32_t mask __maybe_unused = 1 << (it % NUM_INTS_PER_REG);
	uint32_t target, target_shift;

	/* Assigned to group0 */
	assert(!(read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Route it to selected CPUs */
	target = read32(gd->gicd_base +
			GICD_ITARGETSR(it / NUM_TARGETS_PER_REG));
	target_shift = (it % NUM_TARGETS_PER_REG) * ITARGETSR_FIELD_BITS;
	target &= ~(ITARGETSR_FIELD_MASK << target_shift);
	target |= cpu_mask << target_shift;
	DMSG("cpu_mask: writing 0x%x to 0x%" PRIxVA,
	     target, gd->gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG));
	write32(target,
		gd->gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG));
	DMSG("cpu_mask: 0x%x\n",
	     read32(gd->gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG)));
}

static void gic_it_set_prio(struct gic_data *gd, size_t it, uint8_t prio)
{
	size_t idx __maybe_unused = it / NUM_INTS_PER_REG;
	uint32_t mask __maybe_unused = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	assert(!(read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Set prio it to selected CPUs */
	DMSG("prio: writing 0x%x to 0x%" PRIxVA,
		prio, gd->gicd_base + GICD_IPRIORITYR(0) + it);
	write8(prio, gd->gicd_base + GICD_IPRIORITYR(0) + it);
}

static void gic_it_enable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	assert(!(read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));
	if (it >= NUM_SGI) {
		/*
		 * Not enabled yet, except Software Generated Interrupt
		 * which is implementation defined
		 */
		assert(!(read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask));
	}

	/* Enable the interrupt */
	write32(mask, gd->gicd_base + GICD_ISENABLER(idx));
}

static void gic_it_disable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	assert(!(read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Disable the interrupt */
	write32(mask, gd->gicd_base + GICD_ICENABLER(idx));
}

static void gic_it_set_pending(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = BIT32(it % NUM_INTS_PER_REG);

	/* Should be Peripheral Interrupt */
	assert(it >= NUM_SGI);
	/* Assigned to group0 */
	assert(!(read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Raise the interrupt */
	write32(mask, gd->gicd_base + GICD_ISPENDR(idx));
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
	write32(mask, gd->gicd_base + GICD_SGIR);
}

static uint32_t gic_read_iar(struct gic_data *gd)
{
	return read32(gd->gicc_base + GICC_IAR);
}

static void gic_write_eoir(struct gic_data *gd, uint32_t eoir)
{
	write32(eoir, gd->gicc_base + GICC_EOIR);
}

static bool gic_it_is_enabled(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask);
}

static bool __maybe_unused gic_it_get_group(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask);
}

static uint32_t __maybe_unused gic_it_get_target(struct gic_data *gd, size_t it)
{
	size_t reg_idx = it / NUM_TARGETS_PER_REG;
	uint32_t target_shift = (it % NUM_TARGETS_PER_REG) *
				ITARGETSR_FIELD_BITS;
	uint32_t target_mask = ITARGETSR_FIELD_MASK << target_shift;
	uint32_t target =
		read32(gd->gicd_base + GICD_ITARGETSR(reg_idx)) & target_mask;

	target = target >> target_shift;
	return target;
}

void gic_dump_state(struct gic_data *gd)
{
	int i;

	DMSG("GICC_CTLR: 0x%x", read32(gd->gicc_base + GICC_CTLR));
	DMSG("GICD_CTLR: 0x%x", read32(gd->gicd_base + GICD_CTLR));

	for (i = 0; i < (int)gd->max_it; i++) {
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

	if (id == GIC_SPURIOUS_ID)
		DMSG("ignoring spurious interrupt");
	else
		itr_handle(id);

	gic_write_eoir(gd, iar);
}

static void gic_op_add(struct itr_chip *chip, size_t it,
		       uint32_t flags __unused)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it >= gd->max_it)
		panic();

	gic_it_add(gd, it);
	/* Set the CPU mask to deliver interrupts to any online core */
	gic_it_set_cpu_mask(gd, it, 0xff);
	gic_it_set_prio(gd, it, 0x1);
}

static void gic_op_enable(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it >= gd->max_it)
		panic();

	gic_it_enable(gd, it);
}

static void gic_op_disable(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it >= gd->max_it)
		panic();

	gic_it_disable(gd, it);
}

static void gic_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it >= gd->max_it)
		panic();

	gic_it_set_pending(gd, it);
}

static void gic_op_raise_sgi(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	if (it >= gd->max_it)
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

	if (it >= gd->max_it)
		panic();

	gic_it_set_cpu_mask(gd, it, cpu_mask);
}
