/*
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

#include <drivers/gic.h>
#include <io.h>
#include <kernel/tee_core_trace.h>

#include <assert.h>

/* Offsets from gic.gicc_base */
#define GICC_CTLR		(0x000)
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
#define GICD_ICPENDR(n)		(0x280 + (n) * 4)
#define GICD_IPRIORITYR(n)	(0x400 + (n) * 4)
#define GICD_ITARGETSR(n)	(0x800 + (n) * 4)

#define GICD_CTLR_ENABLEGRP0	(1 << 0)
#define GICD_CTLR_ENABLEGRP1	(1 << 1)

/* Number of Private Peripheral Interrupt */
#define NUM_PPI	32

/* Number of interrupts in one register */
#define NUM_INTS_PER_REG	32

/* Number of targets in one register */
#define NUM_TARGETS_PER_REG	4

/* Accessors to access ITARGETSRn */
#define ITARGETSR_FIELD_BITS	8
#define ITARGETSR_FIELD_MASK	0xff

/* Maximum number of interrups a GIC can support */
#define GIC_MAX_INTS		1020


static struct {
	vaddr_t gicc_base;
	vaddr_t gicd_base;
	size_t max_it;
} gic;

static size_t probe_max_it(void)
{
	int i;
	uint32_t old_ctlr;
	size_t ret = 0;

	/*
	 * Probe which interrupt number is the largest.
	 */
	old_ctlr = read32(gic.gicc_base + GICC_CTLR);
	write32(0, gic.gicc_base + GICC_CTLR);
	for (i = GIC_MAX_INTS / NUM_INTS_PER_REG; i > 0; i--) {
		uint32_t old_reg;
		uint32_t reg;
		int b;

		old_reg = read32(gic.gicd_base + GICD_ISENABLER(i));
		write32(0xffffffff, gic.gicd_base + GICD_ISENABLER(i));
		reg = read32(gic.gicd_base + GICD_ISENABLER(i));
		write32(old_reg, gic.gicd_base + GICD_ICENABLER(i));
		for (b = NUM_INTS_PER_REG - 1; b > 0; b--) {
			if ((1 << b) & reg) {
				ret = i * NUM_INTS_PER_REG + b;
				goto out;
			}
		}
	}
out:
	write32(old_ctlr, gic.gicc_base + GICC_CTLR);
	return ret;
}

void gic_init(vaddr_t gicc_base, vaddr_t gicd_base)
{
	size_t n;

	gic.gicc_base = gicc_base;
	gic.gicd_base = gicd_base;
	gic.max_it = probe_max_it();

	for (n = 0; n <= gic.max_it / NUM_INTS_PER_REG; n++) {
		/* Disable interrupts */
		write32(0xffffffff, gic.gicd_base + GICD_ICENABLER(n));

		/* Make interrupts non-pending */
		write32(0xffffffff, gic.gicd_base + GICD_ICPENDR(n));

		/* Mark interrupts non-secure */
		write32(0xffffffff, gic.gicd_base + GICD_IGROUPR(n));
	}

	/* Enable GIC */
	write32(GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN,
		gic.gicc_base + GICC_CTLR);
	write32(GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1,
		gic.gicd_base + GICD_CTLR);
}

void gic_init_base_addr(vaddr_t gicc_base, vaddr_t gicd_base)
{
	gic.gicc_base = gicc_base;
	gic.gicd_base = gicd_base;
	gic.max_it = probe_max_it();
}

void gic_it_add(size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(it <= gic.max_it); /* Not too large */

	/* Disable the interrupt */
	write32(mask, gic.gicd_base + GICD_ICENABLER(idx));
	/* Make it non-pending */
	write32(mask, gic.gicd_base + GICD_ICPENDR(idx));
	/* Assign it to group0 */
	write32(read32(gic.gicd_base + GICD_IGROUPR(idx)) & ~mask,
			gic.gicd_base + GICD_IGROUPR(idx));
}

void gic_it_set_cpu_mask(size_t it, uint8_t cpu_mask)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	uint32_t target, target_shift;

	assert(it <= gic.max_it); /* Not too large */
	/* Assigned to group0 */
	assert(!(read32(gic.gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Route it to selected CPUs */
	target = read32(gic.gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG));
	target_shift = (it % NUM_TARGETS_PER_REG) * ITARGETSR_FIELD_BITS;
	target &= ~(ITARGETSR_FIELD_MASK << target_shift);
	target |= cpu_mask << target_shift;
	DMSG("cpu_mask: writing 0x%x to 0x%x\n",
		target, gic.gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG));
	write32(target, gic.gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG));
	DMSG("cpu_mask: 0x%x\n",
		read32(gic.gicd_base + GICD_ITARGETSR(it / NUM_TARGETS_PER_REG)));
}

void gic_it_set_prio(size_t it, uint8_t prio)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(it <= gic.max_it); /* Not too large */
	/* Assigned to group0 */
	assert(!(read32(gic.gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Set prio it to selected CPUs */
	DMSG("prio: writing 0x%x to 0x%x\n",
		prio, gic.gicd_base + GICD_IPRIORITYR(0) + it);
	write8(prio, gic.gicd_base + GICD_IPRIORITYR(0) + it);
}

void gic_it_enable(size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(it <= gic.max_it); /* Not too large */
	/* Assigned to group0 */
	assert(!(read32(gic.gicd_base + GICD_IGROUPR(idx)) & mask));
	/* Not enabled yet */
	assert(!(read32(gic.gicd_base + GICD_ISENABLER(idx)) & mask));

	/* Enable the interrupt */
	write32(mask, gic.gicd_base + GICD_ISENABLER(idx));
}

void gic_it_disable(size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(it <= gic.max_it); /* Not too large */
	/* Assigned to group0 */
	assert(!(read32(gic.gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Disable the interrupt */
	write32(mask, gic.gicd_base + GICD_ICENABLER(idx));
}

uint32_t gic_read_iar(void)
{
	return read32(gic.gicc_base + GICC_IAR);
}

void gic_write_eoir(uint32_t eoir)
{
	write32(eoir, gic.gicc_base + GICC_EOIR);
}

bool gic_it_is_enabled(size_t it) {
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(read32(gic.gicd_base + GICD_ISENABLER(idx)) & mask);
}

bool gic_it_get_group(size_t it) {
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(read32(gic.gicd_base + GICD_IGROUPR(idx)) & mask);
}

uint32_t gic_it_get_target(size_t it) {
	size_t reg_idx = it / NUM_TARGETS_PER_REG;
	uint32_t target_shift = (it % NUM_TARGETS_PER_REG) * ITARGETSR_FIELD_BITS;
	uint32_t target_mask = ITARGETSR_FIELD_MASK << target_shift;
	uint32_t target =
		read32(gic.gicd_base + GICD_ITARGETSR(reg_idx)) & target_mask;
	target = target >> target_shift;
	return target;
}

void gic_dump_state(void)
{
	int i;
	DMSG("GICC_CTLR: 0x%x", read32(gic.gicc_base + GICC_CTLR));
	DMSG("GICD_CTLR: 0x%x", read32(gic.gicd_base + GICD_CTLR));

	for (i = 0; i < NUM_PPI; i++) {
		if (gic_it_is_enabled(i)) {
			DMSG("irq%d: enabled, group:%d, target:%x", i,
				gic_it_get_group(i), gic_it_get_target(i));
		}
	}
}
