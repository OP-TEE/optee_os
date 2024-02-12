// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, 2023-2024 Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <drivers/gic.h>
#include <dt-bindings/interrupt-controller/arm-gic.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <trace.h>
#include <util.h>

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
#define GICD_IGROUPMODR(n)	(0xd00 + (n) * 4)
#define GICD_SGIR		(0xF00)

#ifdef CFG_ARM_GICV3
#define GICD_PIDR2		(0xFFE8)
#else
/* Called ICPIDR2 in GICv2 specification */
#define GICD_PIDR2		(0xFE8)
#endif

#define GICD_CTLR_ENABLEGRP0	BIT32(0)
#define GICD_CTLR_ENABLEGRP1NS	BIT32(1)
#define GICD_CTLR_ENABLEGRP1S	BIT32(2)
#define GICD_CTLR_ARE_S		BIT32(4)
#define GICD_CTLR_ARE_NS	BIT32(5)

/* Offsets from gic.gicr_base[core_pos] */
#define GICR_V3_PCPUBASE_SIZE	(2 * 64 * 1024)
#define GICR_SGI_BASE_OFFSET	(64 * 1024)
#define GICR_CTLR		(0x00)
#define GICR_TYPER		(0x08)

#define GICR_IGROUPR0		(GICR_SGI_BASE_OFFSET + 0x080)
#define GICR_IGRPMODR0		(GICR_SGI_BASE_OFFSET + 0xD00)
#define GICR_ICENABLER0		(GICR_SGI_BASE_OFFSET + 0x180)
#define GICR_ICPENDR0		(GICR_SGI_BASE_OFFSET + 0x280)
#define GICR_ISENABLER0		(GICR_SGI_BASE_OFFSET + 0x100)
#define GICR_ICFGR0		(GICR_SGI_BASE_OFFSET + 0xC00)
#define GICR_ICFGR1		(GICR_SGI_BASE_OFFSET + 0xC04)
#define GICR_IPRIORITYR(n)	(GICR_SGI_BASE_OFFSET + 0x400 + (n) * 4)

#define GICR_CTLR_RWP		BIT32(3)

#define GICR_TYPER_LAST		BIT64(4)
#define GICR_TYPER_AFF3_SHIFT	56
#define GICR_TYPER_AFF2_SHIFT	48
#define GICR_TYPER_AFF1_SHIFT	40
#define GICR_TYPER_AFF0_SHIFT	32

/* GICD IDR2 name differs on GICv3 and GICv2 but uses same bit map */
#define GICD_PIDR2_ARCHREV_SHIFT	4
#define GICD_PIDR2_ARCHREV_MASK		0xF

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

#define GICD_TYPER_IT_LINES_NUM_MASK	0x1f
#define GICC_IAR_IT_ID_MASK	0x3ff
#define GICC_IAR_CPU_ID_MASK	0x7
#define GICC_IAR_CPU_ID_SHIFT	10

#define GICC_SGI_IRM_BIT	40
#define GICC_SGI_AFF1_SHIFT	16
#define GICC_SGI_AFF2_SHIFT	32
#define GICC_SGI_AFF3_SHIFT	48

#define GICD_SGIR_SIGINTID_MASK			0xf
#define GICD_SGIR_TO_OTHER_CPUS			0x1
#define GICD_SGIR_TO_THIS_CPU			0x2
#define GICD_SGIR_TARGET_LIST_FILTER_SHIFT	24
#define GICD_SGIR_NSATT_SHIFT			15
#define GICD_SGIR_CPU_TARGET_LIST_SHIFT		16

struct gic_data {
	vaddr_t gicc_base;
	vaddr_t gicd_base;
#if defined(CFG_ARM_GICV3)
	vaddr_t gicr_base[CFG_TEE_CORE_NB_CORE];
#endif
	size_t max_it;
	uint32_t per_cpu_group_status;
	uint32_t per_cpu_group_modifier;
	uint32_t per_cpu_enable;
	struct itr_chip chip;
};

static bool gic_primary_done __nex_bss;
static struct gic_data gic_data __nex_bss;

static void gic_op_add(struct itr_chip *chip, size_t it, uint32_t type,
		       uint32_t prio);
static void gic_op_enable(struct itr_chip *chip, size_t it);
static void gic_op_disable(struct itr_chip *chip, size_t it);
static void gic_op_raise_pi(struct itr_chip *chip, size_t it);
static void gic_op_raise_sgi(struct itr_chip *chip, size_t it,
			     uint32_t cpu_mask);
static void gic_op_set_affinity(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask);

static const struct itr_ops gic_ops = {
	.add = gic_op_add,
	.mask = gic_op_disable,
	.unmask = gic_op_enable,
	.enable = gic_op_enable,
	.disable = gic_op_disable,
	.raise_pi = gic_op_raise_pi,
	.raise_sgi = gic_op_raise_sgi,
	.set_affinity = gic_op_set_affinity,
};
DECLARE_KEEP_PAGER(gic_ops);

static vaddr_t __maybe_unused get_gicr_base(struct gic_data *gd __maybe_unused)
{
#if defined(CFG_ARM_GICV3)
	return gd->gicr_base[get_core_pos()];
#else
	return 0;
#endif
}

static bool affinity_routing_is_enabled(struct gic_data *gd)
{
	return IS_ENABLED(CFG_ARM_GICV3) &&
	       io_read32(gd->gicd_base + GICD_CTLR) & GICD_CTLR_ARE_S;
}

static size_t probe_max_it(vaddr_t gicc_base __maybe_unused, vaddr_t gicd_base)
{
	int i;
	uint32_t old_ctlr;
	size_t ret = 0;
	size_t max_regs = io_read32(gicd_base + GICD_TYPER) &
			  GICD_TYPER_IT_LINES_NUM_MASK;

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

static void gicr_wait_for_pending_write(vaddr_t gicr_base)
{
	/*
	 * Wait for changes to
	 * - GICR_ICENABLER0
	 * - GICR_CTLR.DPG1S
	 * - GICR_CTLR.DPG1NS
	 * - GICR_CTLR.DPG0
	 * to be visible to all agents in the system.
	 */
	while (io_read32(gicr_base + GICR_CTLR) & GICR_CTLR_RWP)
		;
}

static void gicv3_sync_redist_config(struct gic_data *gd)
{
	vaddr_t gicr_base = get_gicr_base(gd);
	bool need_sync = false;
	uint32_t gmod0 = 0;
	uint32_t grp0 = 0;
	size_t n = 0;

	/*
	 * If gicr_base isn't available there's no need to synchronize SGI
	 * configuration since gic_init_donate_sgi_to_ns() would panic.
	 */
	if (!gicr_base)
		return;

	grp0 = io_read32(gicr_base + GICR_IGROUPR0);
	gmod0 = io_read32(gicr_base + GICR_IGRPMODR0);
	for (n = GIC_SGI_SEC_BASE; n < GIC_SPI_BASE; n++) {
		/* Ignore matching bits */
		if (!(BIT32(n) & (grp0 ^ gd->per_cpu_group_status)) &&
		    !(BIT32(n) & (gmod0 ^ gd->per_cpu_group_modifier)))
			continue;
		/*
		 * SGI/PPI-n differs from primary CPU configuration,
		 * let's sync up.
		 */
		need_sync = true;

		/* Disable interrupt */
		io_write32(gicr_base + GICR_ICENABLER0, BIT32(n));

		/* Wait for the write to GICR_ICENABLER0 to propagate */
		gicr_wait_for_pending_write(gicr_base);

		/* Make interrupt non-pending */
		io_write32(gicr_base + GICR_ICPENDR0, BIT32(n));

		if (BIT32(n) & gd->per_cpu_group_status)
			grp0 |= BIT32(n);
		else
			grp0 &= ~BIT32(n);
		if (BIT32(n) & gd->per_cpu_group_modifier)
			gmod0 |= BIT32(n);
		else
			gmod0 &= ~BIT32(n);
	}

	if (need_sync) {
		io_write32(gicr_base + GICR_IGROUPR0, grp0);
		io_write32(gicr_base + GICR_IGRPMODR0, gmod0);
		io_write32(gicr_base + GICR_ISENABLER0, gd->per_cpu_enable);
	}
}

static void gic_legacy_sync_dist_config(struct gic_data *gd)
{
	bool need_sync = false;
	uint32_t grp0 = 0;
	size_t n = 0;

	grp0 = io_read32(gd->gicd_base + GICD_IGROUPR(0));
	for (n = GIC_SGI_SEC_BASE; n < GIC_SPI_BASE; n++) {
		/* Ignore matching bits */
		if (!(BIT32(n) & (grp0 ^ gd->per_cpu_group_status)))
			continue;
		/*
		 * SGI/PPI-n differs from primary CPU configuration,
		 * let's sync up.
		 */
		need_sync = true;

		/* Disable interrupt */
		io_write32(gd->gicd_base + GICD_ICENABLER(0), BIT(n));

		/* Make interrupt non-pending */
		io_write32(gd->gicd_base + GICD_ICPENDR(0), BIT(n));

		if (BIT32(n) & gd->per_cpu_group_status)
			grp0 |= BIT32(n);
		else
			grp0 &= ~BIT32(n);
	}

	if (need_sync) {
		io_write32(gd->gicd_base + GICD_IGROUPR(0), grp0);
		io_write32(gd->gicd_base + GICD_ISENABLER(0),
			   gd->per_cpu_enable);
	}
}

static void init_gic_per_cpu(struct gic_data *gd)
{
	io_write32(gd->gicd_base + GICD_IGROUPR(0), gd->per_cpu_group_status);

	/*
	 * Set the priority mask to permit Non-secure interrupts, and to
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

void gic_init_per_cpu(void)
{
	struct gic_data *gd = &gic_data;

#if defined(CFG_ARM_GICV3)
	assert(gd->gicd_base);
#else
	assert(gd->gicd_base && gd->gicc_base);
#endif

	if (IS_ENABLED(CFG_WITH_ARM_TRUSTED_FW)) {
		/*
		 * GIC is already initialized by TF-A, we only need to
		 * handle eventual SGI or PPI configuration changes.
		 */
		if (affinity_routing_is_enabled(gd))
			gicv3_sync_redist_config(gd);
		else
			gic_legacy_sync_dist_config(gd);
	} else {
		/*
		 * Non-TF-A case where all CPU specific configuration
		 * of GIC must be done here.
		 */
		init_gic_per_cpu(gd);
	}
}

void gic_init_donate_sgi_to_ns(size_t it)
{
	struct gic_data *gd = &gic_data;

	assert(it >= GIC_SGI_SEC_BASE && it <= GIC_SGI_SEC_MAX);

	/* Assert it's secure to start with. */
	assert(!(gd->per_cpu_group_status & BIT32(it)) &&
	       (gd->per_cpu_group_modifier & BIT32(it)));

	gd->per_cpu_group_modifier &= ~BIT32(it);
	gd->per_cpu_group_status |= BIT32(it);

	if (affinity_routing_is_enabled(gd)) {
		vaddr_t gicr_base = get_gicr_base(gd);

		if (!gicr_base)
			panic("GICR_BASE missing");

		/* Disable interrupt */
		io_write32(gicr_base + GICR_ICENABLER0, BIT32(it));

		/* Wait for the write to GICR_ICENABLER0 to propagate */
		gicr_wait_for_pending_write(gicr_base);

		/* Make interrupt non-pending */
		io_write32(gicr_base + GICR_ICPENDR0, BIT32(it));

		/* Make it to non-secure */
		io_write32(gicr_base + GICR_IGROUPR0, gd->per_cpu_group_status);
		io_write32(gicr_base + GICR_IGRPMODR0,
			   gd->per_cpu_group_modifier);
	} else {
		/* Disable interrupt */
		io_write32(gd->gicd_base + GICD_ICENABLER(0), BIT(it));

		/* Make interrupt non-pending */
		io_write32(gd->gicd_base + GICD_ICPENDR(0), BIT(it));

		/* Make it to non-secure */
		io_write32(gd->gicd_base + GICD_IGROUPR(0),
			   gd->per_cpu_group_status);
	}
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
	case GIC_PPI:
		it_num += 16;
		break;
	case GIC_SPI:
		it_num += 32;
		break;
	default:
		it_num = DT_INFO_INVALID_INTERRUPT;
	}

	return it_num;
}

static void __maybe_unused probe_redist_base_addrs(vaddr_t *gicr_base_addrs,
						   paddr_t gicr_base_pa)
{
	size_t sz = GICR_V3_PCPUBASE_SIZE;
	paddr_t pa = gicr_base_pa;
	size_t core_pos = 0;
	uint64_t mt_bit = 0;
	uint64_t mpidr = 0;
	uint64_t tv = 0;
	vaddr_t va = 0;

#ifdef ARM64
	mt_bit = read_mpidr_el1() & MPIDR_MT_MASK;
#endif
	do {
		va = core_mmu_get_va(pa, MEM_AREA_IO_SEC, sz);
		if (!va)
			panic();
		tv = io_read64(va + GICR_TYPER);

		/*
		 * Extract an mpidr from the Type register to calculate the
		 * core position of this redistributer instance.
		 */
		mpidr = mt_bit;
		mpidr |= SHIFT_U64((tv >> GICR_TYPER_AFF3_SHIFT) &
				   MPIDR_AFFLVL_MASK, MPIDR_AFF3_SHIFT);
		mpidr |= (tv >> GICR_TYPER_AFF0_SHIFT) &
			 (MPIDR_AFF0_MASK | MPIDR_AFF1_MASK | MPIDR_AFF2_MASK);
		core_pos = get_core_pos_mpidr(mpidr);
		if (core_pos < CFG_TEE_CORE_NB_CORE) {
			DMSG("GICR_BASE[%zu] at %#"PRIxVA, core_pos, va);
			gicr_base_addrs[core_pos] = va;
		} else {
			EMSG("Skipping too large core_pos %zu from GICR_TYPER",
			     core_pos);
		}
		pa += sz;
	} while (!(tv & GICR_TYPER_LAST));
}

static void gic_init_base_addr(paddr_t gicc_base_pa, paddr_t gicd_base_pa,
			       paddr_t gicr_base_pa __maybe_unused)
{
	struct gic_data *gd = &gic_data;
	vaddr_t gicc_base = 0;
	vaddr_t gicd_base = 0;
	uint32_t vers __maybe_unused = 0;

	assert(cpu_mmu_enabled());

	gicd_base = core_mmu_get_va(gicd_base_pa, MEM_AREA_IO_SEC,
				    GIC_DIST_REG_SIZE);
	if (!gicd_base)
		panic();

	vers = io_read32(gicd_base + GICD_PIDR2);
	vers >>= GICD_PIDR2_ARCHREV_SHIFT;
	vers &= GICD_PIDR2_ARCHREV_MASK;

	if (IS_ENABLED(CFG_ARM_GICV3)) {
		assert(vers == 3);
	} else {
		assert(vers == 2 || vers == 1);
		gicc_base = core_mmu_get_va(gicc_base_pa, MEM_AREA_IO_SEC,
					    GIC_CPU_REG_SIZE);
		if (!gicc_base)
			panic();
	}

	gd->gicc_base = gicc_base;
	gd->gicd_base = gicd_base;
	gd->max_it = probe_max_it(gicc_base, gicd_base);
#if defined(CFG_ARM_GICV3)
	if (affinity_routing_is_enabled(gd) && gicr_base_pa)
		probe_redist_base_addrs(gd->gicr_base, gicr_base_pa);
#endif
	gd->chip.ops = &gic_ops;

	if (IS_ENABLED(CFG_DT))
		gd->chip.dt_get_irq = gic_dt_get_irq;
}

void gic_init_v3(paddr_t gicc_base_pa, paddr_t gicd_base_pa,
		 paddr_t gicr_base_pa)
{
	struct gic_data __maybe_unused *gd = &gic_data;
	size_t __maybe_unused n = 0;

	gic_init_base_addr(gicc_base_pa, gicd_base_pa, gicr_base_pa);

#if defined(CFG_WITH_ARM_TRUSTED_FW)
	/* GIC configuration is initialized from TF-A when embedded */
	if (affinity_routing_is_enabled(gd)) {
		/* Secure affinity routing enabled */
		vaddr_t gicr_base = get_gicr_base(gd);

		if (gicr_base) {
			gd->per_cpu_group_status = io_read32(gicr_base +
							     GICR_IGROUPR0);
			gd->per_cpu_group_modifier = io_read32(gicr_base +
							       GICR_IGRPMODR0);
		} else {
			IMSG("GIC redistributor base address not provided");
			IMSG("Assuming default GIC group status and modifier");
			gd->per_cpu_group_status = 0xffff00ff;
			gd->per_cpu_group_modifier = ~gd->per_cpu_group_status;
		}
	} else {
		/* Legacy operation with secure affinity routing disabled */
		gd->per_cpu_group_status = io_read32(gd->gicd_base +
						     GICD_IGROUPR(0));
		gd->per_cpu_group_modifier = ~gd->per_cpu_group_status;
	}
#else /*!CFG_WITH_ARM_TRUSTED_FW*/
	/*
	 * Without TF-A, GIC is always configured in for legacy operation
	 * with secure affinity routing disabled.
	 */
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
			gd->per_cpu_group_status = 0xffff00ff;
			gd->per_cpu_group_modifier = ~gd->per_cpu_group_status;
			io_write32(gd->gicd_base + GICD_IGROUPR(n),
				   gd->per_cpu_group_status);
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
		     GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1NS);
#endif
#endif /*!CFG_WITH_ARM_TRUSTED_FW*/

	interrupt_main_init(&gic_data.chip);
}

static void gic_it_add(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(gd == &gic_data);

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

	assert(gd == &gic_data);

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

	assert(gd == &gic_data);

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

	assert(gd == &gic_data);

	/* Assigned to group0 */
	assert(!(io_read32(base + GICD_IGROUPR(idx)) & mask));

	/* Enable the interrupt */
	io_write32(base + GICD_ISENABLER(idx), mask);
}

static void gic_it_disable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(gd == &gic_data);

	/* Assigned to group0 */
	assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Disable the interrupt */
	io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
}

static void gic_it_set_pending(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = BIT32(it % NUM_INTS_PER_REG);

	assert(gd == &gic_data);

	/* Should be Peripheral Interrupt */
	assert(it >= NUM_SGI);

	/* Raise the interrupt */
	io_write32(gd->gicd_base + GICD_ISPENDR(idx), mask);
}

static void assert_cpu_mask_is_valid(uint32_t cpu_mask)
{
	bool __maybe_unused to_others = cpu_mask & ITR_CPU_MASK_TO_OTHER_CPUS;
	bool __maybe_unused to_current = cpu_mask & ITR_CPU_MASK_TO_THIS_CPU;
	bool __maybe_unused to_list = cpu_mask & 0xff;

	/* One and only one of the bit fields shall be non-zero */
	assert(to_others + to_current + to_list == 1);
}

static void gic_it_raise_sgi(struct gic_data *gd __maybe_unused, size_t it,
			     uint32_t cpu_mask, bool ns)
{
#if defined(CFG_ARM_GICV3)
	uint32_t mask_id = it & 0xf;
	uint64_t mask = SHIFT_U64(mask_id, 24);

	assert_cpu_mask_is_valid(cpu_mask);

	if (cpu_mask & ITR_CPU_MASK_TO_OTHER_CPUS) {
		mask |= BIT64(GICC_SGI_IRM_BIT);
	} else {
		uint64_t mpidr = read_mpidr();
		uint64_t mask_aff1 = (mpidr & MPIDR_AFF1_MASK) >>
				     MPIDR_AFF1_SHIFT;
		uint64_t mask_aff2 = (mpidr & MPIDR_AFF2_MASK) >>
				     MPIDR_AFF2_SHIFT;
		uint64_t mask_aff3 = (mpidr & MPIDR_AFF3_MASK) >>
				     MPIDR_AFF3_SHIFT;

		mask |= SHIFT_U64(mask_aff1, GICC_SGI_AFF1_SHIFT);
		mask |= SHIFT_U64(mask_aff2, GICC_SGI_AFF2_SHIFT);
		mask |= SHIFT_U64(mask_aff3, GICC_SGI_AFF3_SHIFT);

		if (cpu_mask & ITR_CPU_MASK_TO_THIS_CPU) {
			mask |= BIT32(mpidr & 0xf);
		} else {
			/*
			 * Only support sending SGI to the cores in the
			 * same cluster now.
			 */
			mask |= cpu_mask & 0xff;
		}
	}

	/* Raise the interrupt */
	if (ns)
		write_icc_asgi1r(mask);
	else
		write_icc_sgi1r(mask);
#else
	uint32_t mask_id = it & GICD_SGIR_SIGINTID_MASK;
	uint32_t mask_group = ns;
	uint32_t mask = mask_id;

	assert_cpu_mask_is_valid(cpu_mask);

	mask |= SHIFT_U32(mask_group, GICD_SGIR_NSATT_SHIFT);
	if (cpu_mask & ITR_CPU_MASK_TO_OTHER_CPUS) {
		mask |= SHIFT_U32(GICD_SGIR_TO_OTHER_CPUS,
				  GICD_SGIR_TARGET_LIST_FILTER_SHIFT);
	} else if (cpu_mask & ITR_CPU_MASK_TO_THIS_CPU) {
		mask |= SHIFT_U32(GICD_SGIR_TO_THIS_CPU,
				  GICD_SGIR_TARGET_LIST_FILTER_SHIFT);
	} else {
		mask |= SHIFT_U32(cpu_mask & 0xff,
				  GICD_SGIR_CPU_TARGET_LIST_SHIFT);
	}

	/* Raise the interrupt */
	io_write32(gd->gicd_base + GICD_SGIR, mask);
#endif
}

static uint32_t gic_read_iar(struct gic_data *gd __maybe_unused)
{
	assert(gd == &gic_data);

#if defined(CFG_ARM_GICV3)
	return read_icc_iar1();
#else
	return io_read32(gd->gicc_base + GICC_IAR);
#endif
}

static void gic_write_eoir(struct gic_data *gd __maybe_unused, uint32_t eoir)
{
	assert(gd == &gic_data);

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

	assert(gd == &gic_data);
	return !!(io_read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask);
}

static bool __maybe_unused gic_it_get_group(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	assert(gd == &gic_data);
	return !!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask);
}

static uint32_t __maybe_unused gic_it_get_target(struct gic_data *gd, size_t it)
{
	size_t reg_idx = it / NUM_TARGETS_PER_REG;
	uint32_t target_shift = (it % NUM_TARGETS_PER_REG) *
				ITARGETSR_FIELD_BITS;
	uint32_t target_mask = ITARGETSR_FIELD_MASK << target_shift;
	uint32_t target = io_read32(gd->gicd_base + GICD_ITARGETSR(reg_idx));

	assert(gd == &gic_data);
	return (target & target_mask) >> target_shift;
}

void gic_dump_state(void)
{
	struct gic_data *gd = &gic_data;
	int i = 0;

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

static void __maybe_unused gic_native_itr_handler(void)
{
	struct gic_data *gd = &gic_data;
	uint32_t iar = 0;
	uint32_t id = 0;

	iar = gic_read_iar(gd);
	id = iar & GICC_IAR_IT_ID_MASK;

	if (id <= gd->max_it)
		interrupt_call_handlers(&gd->chip, id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);

	gic_write_eoir(gd, iar);
}

#ifndef CFG_CORE_WORKAROUND_ARM_NMFI
/* Override interrupt_main_handler() with driver implementation */
void interrupt_main_handler(void)
{
	gic_native_itr_handler();
}
#endif /*CFG_CORE_WORKAROUND_ARM_NMFI*/

static void gic_op_add(struct itr_chip *chip, size_t it,
		       uint32_t type __unused,
		       uint32_t prio __unused)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	assert(gd == &gic_data);

	if (it > gd->max_it)
		panic();

	if (it < GIC_SPI_BASE) {
		if (gic_primary_done)
			panic("Cannot add SGI or PPI after boot");

		/* Assign it to Secure Group 1, G1S */
		gd->per_cpu_group_modifier |= BIT32(it);
		gd->per_cpu_group_status &= ~BIT32(it);
	}

	if (it < GIC_SPI_BASE && affinity_routing_is_enabled(gd)) {
		vaddr_t gicr_base = get_gicr_base(gd);

		if (!gicr_base)
			panic("GICR_BASE missing");

		/* Disable interrupt */
		io_write32(gicr_base + GICR_ICENABLER0, BIT32(it));

		/* Wait for the write to GICR_ICENABLER0 to propagate */
		gicr_wait_for_pending_write(gicr_base);

		/* Make interrupt non-pending */
		io_write32(gicr_base + GICR_ICPENDR0, BIT32(it));

		/* Make it to Secure */
		io_write32(gicr_base + GICR_IGROUPR0, gd->per_cpu_group_status);
		io_write32(gicr_base + GICR_IGRPMODR0,
			   gd->per_cpu_group_modifier);
	} else {
		gic_it_add(gd, it);
		/* Set the CPU mask to deliver interrupts to any online core */
		gic_it_set_cpu_mask(gd, it, 0xff);
		gic_it_set_prio(gd, it, 0x1);
	}
}

static void gic_op_enable(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	assert(gd == &gic_data);

	if (it > gd->max_it)
		panic();

	if (it < GIC_SPI_BASE)
		gd->per_cpu_enable |= BIT(it);

	if (it < GIC_SPI_BASE && affinity_routing_is_enabled(gd)) {
		vaddr_t gicr_base = get_gicr_base(gd);

		if (!gicr_base)
			panic("GICR_BASE missing");

		/* Assigned to G1S */
		assert(gd->per_cpu_group_modifier & BIT(it) &&
		       !(gd->per_cpu_group_status & BIT(it)));
		io_write32(gicr_base + GICR_ISENABLER0, gd->per_cpu_enable);
	} else {
		gic_it_enable(gd, it);
	}
}

static void gic_op_disable(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	assert(gd == &gic_data);

	if (it > gd->max_it)
		panic();

	gic_it_disable(gd, it);
}

static void gic_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	assert(gd == &gic_data);

	if (it > gd->max_it)
		panic();

	gic_it_set_pending(gd, it);
}

static void gic_op_raise_sgi(struct itr_chip *chip, size_t it,
			     uint32_t cpu_mask)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);
	bool ns = false;

	assert(gd == &gic_data);

	/* Should be Software Generated Interrupt */
	assert(it < NUM_SGI);

	ns = BIT32(it) & gd->per_cpu_group_status;
	gic_it_raise_sgi(gd, it, cpu_mask, ns);
}

static void gic_op_set_affinity(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask)
{
	struct gic_data *gd = container_of(chip, struct gic_data, chip);

	assert(gd == &gic_data);

	if (it > gd->max_it)
		panic();

	gic_it_set_cpu_mask(gd, it, cpu_mask);
}

#ifdef CFG_DT
/* Callback for "interrupts" and "interrupts-extended" DT node properties */
static TEE_Result dt_get_gic_chip_cb(struct dt_pargs *arg, void *priv_data,
				     struct itr_desc *itr_desc)
{
	int itr_num = DT_INFO_INVALID_INTERRUPT;
	struct itr_chip *chip = priv_data;
	uint32_t phandle_args[2] = { };
	uint32_t type = 0;
	uint32_t prio = 0;

	assert(arg && itr_desc);

	/*
	 * gic_dt_get_irq() expects phandle arguments passed are still in DT
	 * format (big-endian) whereas struct dt_pargs carries converted
	 * formats. Therefore swap again phandle arguments. gic_dt_get_irq()
	 * consumes only the 2 first arguments.
	 */
	if (arg->args_count < 2)
		return TEE_ERROR_GENERIC;
	phandle_args[0] = cpu_to_fdt32(arg->args[0]);
	phandle_args[1] = cpu_to_fdt32(arg->args[1]);

	itr_num = gic_dt_get_irq((const void *)phandle_args, 2, &type, &prio);
	if (itr_num == DT_INFO_INVALID_INTERRUPT)
		return TEE_ERROR_GENERIC;

	gic_op_add(chip, itr_num, type, prio);

	itr_desc->chip = chip;
	itr_desc->itr_num = itr_num;

	return TEE_SUCCESS;
}

static TEE_Result gic_probe(const void *fdt, int offs, const void *cd __unused)
{
	if (interrupt_register_provider(fdt, offs, dt_get_gic_chip_cb,
					&gic_data.chip))
		panic();

	return TEE_SUCCESS;
}

static const struct dt_device_match gic_match_table[] = {
	{ .compatible = "arm,cortex-a15-gic" },
	{ .compatible = "arm,cortex-a7-gic" },
	{ .compatible = "arm,cortex-a5-gic" },
	{ .compatible = "arm,cortex-a9-gic" },
	{ .compatible = "arm,gic-400" },
	{ }
};

DEFINE_DT_DRIVER(gic_dt_driver) = {
	.name = "gic",
	.match_table = gic_match_table,
	.probe = gic_probe,
};
#endif /*CFG_DT*/

static TEE_Result gic_set_primary_done(void)
{
	gic_primary_done = true;
	return TEE_SUCCESS;
}

nex_release_init_resource(gic_set_primary_done);
