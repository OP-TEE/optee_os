// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <assert.h>
#include <config.h>
#include <drivers/plic.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <trace.h>

#define PLIC_PRIORITY_OFFSET		0
#define PLIC_PENDING_OFFSET		0x1000
#define PLIC_ENABLE_OFFSET		0x2000
#define PLIC_THRESHOLD_OFFSET		0x200000
#define PLIC_CLAIM_OFFSET		0x200004

#define PLIC_PRIORITY_SHIFT_PER_SOURCE	U(2)
#define PLIC_PENDING_SHIFT_PER_SOURCE	U(0)

#define PLIC_ENABLE_SHIFT_PER_TARGET	U(7)
#define PLIC_THRESHOLD_SHIFT_PER_TARGET	U(12)
#define PLIC_CLAIM_SHIFT_PER_TARGET	U(12)

#define PLIC_PRIORITY(base, source) \
		((base) + PLIC_PRIORITY_OFFSET + \
		SHIFT_U32(source, PLIC_PRIORITY_SHIFT_PER_SOURCE) \
	)
#define PLIC_PENDING(base, source) \
		((base) + PLIC_PENDING_OFFSET + \
		(4 * ((source) / 32)) \
	)
#define PLIC_ENABLE(base, source, hart) \
		((base) + PLIC_ENABLE_OFFSET + \
		SHIFT_U32(hart, PLIC_ENABLE_SHIFT_PER_TARGET) +\
		(4 * ((source) / 32)) \
	)
#define PLIC_THRESHOLD(base, hart) \
		((base) + PLIC_THRESHOLD_OFFSET + \
		SHIFT_U32(hart, PLIC_THRESHOLD_SHIFT_PER_TARGET) \
	)
#define PLIC_COMPLETE(base, hart) \
		((base) + PLIC_CLAIM_OFFSET + \
		SHIFT_U32(hart, PLIC_CLAIM_SHIFT_PER_TARGET) \
	)
#define PLIC_CLAIM(base, hart) PLIC_COMPLETE(base, hart)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PLIC_BASE, PLIC_REG_SIZE);

static bool __maybe_unused
plic_is_pending(struct plic_data *pd, uint32_t source)
{
	return io_read32(PLIC_PENDING(pd->plic_base, source)) &
	       BIT(source % 32);
}

static void plic_set_pending(struct plic_data *pd, uint32_t source)
{
	io_setbits32(PLIC_PENDING(pd->plic_base, source), BIT(source % 32));
}

static void plic_enable_interrupt(struct plic_data *pd, uint32_t source)
{
	io_setbits32(PLIC_ENABLE(pd->plic_base, source, get_core_pos()),
		     BIT(source & 0x1f));
}

static uint32_t __maybe_unused
plic_get_interrupt_enable(struct plic_data *pd, uint32_t source)
{
	return io_read32(PLIC_ENABLE(pd->plic_base, source, get_core_pos())) &
	       BIT(source & 0x1f);
}

static void plic_disable_interrupt(struct plic_data *pd, uint32_t source)
{
	io_clrbits32(PLIC_ENABLE(pd->plic_base, source, get_core_pos()),
		     BIT(source & 0x1f));
}

static uint32_t __maybe_unused plic_get_threshold(struct plic_data *pd)
{
	return io_read32(PLIC_THRESHOLD(pd->plic_base, get_core_pos()));
}

static void plic_set_threshold(struct plic_data *pd, uint32_t threshold)
{
	io_write32(PLIC_THRESHOLD(pd->plic_base, get_core_pos()), threshold);
}

static uint32_t __maybe_unused
plic_get_priority(struct plic_data *pd, uint32_t source)
{
	return io_read32(PLIC_PRIORITY(pd->plic_base, source));
}

static void plic_set_priority(struct plic_data *pd, uint32_t source,
			      uint32_t priority)
{
	io_write32(PLIC_PRIORITY(pd->plic_base, source), priority);
}

static uint32_t plic_claim_interrupt(struct plic_data *pd)
{
	return io_read32(PLIC_CLAIM(pd->plic_base, get_core_pos()));
}

static void plic_complete_interrupt(struct plic_data *pd, uint32_t source)
{
	io_write32(PLIC_CLAIM(pd->plic_base, get_core_pos()), source);
}

static void plic_op_add(struct itr_chip *chip, size_t it,
			uint32_t type __unused,
			uint32_t prio)
{
	struct plic_data *pd = container_of(chip, struct plic_data, chip);

	if (it > pd->max_it)
		panic();

	plic_disable_interrupt(pd, it);
	plic_set_priority(pd, it, prio);
}

static void plic_op_enable(struct itr_chip *chip, size_t it)
{
	struct plic_data *pd = container_of(chip, struct plic_data, chip);

	if (it > pd->max_it)
		panic();

	plic_enable_interrupt(pd, it);
}

static void plic_op_disable(struct itr_chip *chip, size_t it)
{
	struct plic_data *pd = container_of(chip, struct plic_data, chip);

	if (it > pd->max_it)
		panic();

	plic_disable_interrupt(pd, it);
}

static void plic_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct plic_data *pd = container_of(chip, struct plic_data, chip);

	if (it > pd->max_it)
		panic();

	plic_set_pending(pd, it);
}

static void plic_op_raise_sgi(struct itr_chip *chip __unused,
			      size_t it __unused, uint8_t cpu_mask __unused)
{
}

static void plic_op_set_affinity(struct itr_chip *chip __unused,
				 size_t it __unused, uint8_t cpu_mask __unused)
{
}

static int plic_dt_get_irq(const uint32_t *properties __unused,
			   int count __unused, uint32_t *type __unused,
			   uint32_t *prio __unused)
{
	return DT_INFO_INVALID_INTERRUPT;
}

static size_t probe_max_it(vaddr_t plic_base __unused)
{
	return PLIC_NUM_SOURCES;
}

static const struct itr_ops plic_ops = {
	.add = plic_op_add,
	.enable = plic_op_enable,
	.disable = plic_op_disable,
	.raise_pi = plic_op_raise_pi,
	.raise_sgi = plic_op_raise_sgi,
	.set_affinity = plic_op_set_affinity,
};

void plic_init_base_addr(struct plic_data *pd, paddr_t plic_base_pa)
{
	vaddr_t plic_base = 0;

	assert(cpu_mmu_enabled());

	plic_base = core_mmu_get_va(plic_base_pa, MEM_AREA_IO_SEC,
				    PLIC_REG_SIZE);
	if (!plic_base)
		panic();

	pd->plic_base = plic_base;
	pd->max_it = probe_max_it(plic_base);
	pd->chip.ops = &plic_ops;

	if (IS_ENABLED(CFG_DT))
		pd->chip.dt_get_irq = plic_dt_get_irq;
}

void plic_hart_init(struct plic_data *pd __unused)
{
	/* TODO: To be called by secondary harts */
}

void plic_init(struct plic_data *pd, paddr_t plic_base_pa)
{
	size_t n = 0;

	plic_init_base_addr(pd, plic_base_pa);

	for (n = 0; n <= pd->max_it; n++) {
		plic_disable_interrupt(pd, n);
		plic_set_priority(pd, n, 1);
	}

	plic_set_threshold(pd, 0);
}

void plic_it_handle(struct plic_data *pd)
{
	uint32_t id = plic_claim_interrupt(pd);

	if (id <= pd->max_it)
		itr_handle(id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);

	plic_complete_interrupt(pd, id);
}
