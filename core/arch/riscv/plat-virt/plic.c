/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 *
 */

#include <assert.h>
#include <config.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <io.h>
#include <platform_config.h>
#include <plic.h>
#include <trace.h>

#define PLIC_PRIORITY_OFFSET			0
#define PLIC_PENDING_OFFSET				0x1000
#define PLIC_ENABLE_OFFSET				0x2000
#define PLIC_THRESHOLD_OFFSET			0x200000
#define PLIC_CLAIM_OFFSET				0x200004

#define PLIC_PRIORITY_SHIFT_PER_SOURCE	U(2)
#define PLIC_PENDING_SHIFT_PER_SOURCE	U(0)

#define PLIC_ENABLE_SHIFT_PER_TARGET	U(7)
#define PLIC_THRESHOLD_SHIFT_PER_TARGET	U(12)
#define PLIC_CLAIM_SHIFT_PER_TARGET		U(12)

// Driver for PLIC implementation for qemu riscv virt machine
#define PLIC_PRIORITY(base, source)	(base + PLIC_PRIORITY_OFFSET +\
								 SHIFT_U32(source, PLIC_PRIORITY_SHIFT_PER_SOURCE))
#define PLIC_PENDING(base, source)	(base + PLIC_PENDING_OFFSET +\
								 (4 * ((source) / 32)))
#define PLIC_ENABLE(base, source, hart)	(base + PLIC_ENABLE_OFFSET +\
									 SHIFT_U32(hart, PLIC_ENABLE_SHIFT_PER_TARGET) +\
									 (4 * ((source) / 32)))
#define PLIC_THRESHOLD(base, hart)	(base + PLIC_THRESHOLD_OFFSET +\
								 SHIFT_U32(hart,PLIC_THRESHOLD_SHIFT_PER_TARGET))
#define PLIC_COMPLETE(base, hart)		(base + PLIC_CLAIM_OFFSET +\
								 SHIFT_U32(hartid,PLIC_CLAIM_SHIFT_PER_TARGET))
#define PLIC_CLAIM(base, hart)		PLIC_COMPLETE(base, hart)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PLIC_BASE, PLIC_REG_SIZE);

static inline bool plic_is_pending(struct plic_data *pd, uint32_t source)
{
	uint32_t current  = io_read32(PLIC_PENDING(pd->plic_base, source));
	return ((current & BIT(source % 32)) != 0);
}

static inline void plic_set_pending(struct plic_data *pd, uint32_t source)
{
	uint32_t current  = io_read32(PLIC_PENDING(pd->plic_base, source));
	current |= BIT(source % 32);
	io_write32(PLIC_PENDING(pd->plic_base, source), current);
}

static inline void plic_enable_interrupt(struct plic_data *pd, uint32_t source)
{
	uint32_t hartid = get_core_pos();
	uint32_t current;

	current = io_read32(PLIC_ENABLE(pd->plic_base, source, hartid));
	current |= BIT(source & 0x1f);
	io_write32(PLIC_ENABLE(pd->plic_base, source, hartid), current);
}

static inline uint32_t plic_get_interrupt_enable(struct plic_data *pd, uint32_t source)
{
	uint32_t hartid = get_core_pos();
	uint32_t current;

	current = io_read32(PLIC_ENABLE(pd->plic_base, source, hartid));
	current = current >> (source & 0x1f);
	return current;
}

static inline void plic_disable_interrupt(struct plic_data *pd, uint32_t source)
{
	uint32_t hartid = get_core_pos();
	uint32_t current = io_read32(PLIC_ENABLE(pd->plic_base, source, hartid));

	current &= (~BIT((source & 0x1f)));
	io_write32(PLIC_ENABLE(pd->plic_base, source, hartid), current);
}

static inline uint32_t plic_get_threshold(struct plic_data *pd)
{
	uint32_t hartid = get_core_pos();
	uint32_t threshold;

	threshold = io_read32(PLIC_THRESHOLD(pd->plic_base, hartid));
	return threshold;
}

static inline void plic_set_threshold(struct plic_data *pd, uint32_t threshold)
{
	uint32_t hartid = get_core_pos();

	io_write32(PLIC_THRESHOLD(pd->plic_base, hartid), threshold);
}

static inline uint32_t plic_get_priority(struct plic_data *pd, uint32_t source)
{
	uint32_t priority;

	priority = io_read32(PLIC_PRIORITY(pd->plic_base, source));

	return priority;
}

static inline void plic_set_priority(struct plic_data *pd, uint32_t source, uint32_t priority)
{
	io_write32(PLIC_PRIORITY(pd->plic_base, source), priority);
}

static inline uint32_t plic_claim_interrupt(struct plic_data *pd)
{
	uint32_t hartid = get_core_pos();
	uint32_t current;
	
	current = io_read32(PLIC_CLAIM(pd->plic_base, hartid));

	return current;
}

static inline void plic_complete_interrupt(struct plic_data *pd, uint32_t source)
{
	uint32_t hartid = get_core_pos();

	io_write32(PLIC_CLAIM(pd->plic_base, hartid), source);
}

static void plic_op_add(struct itr_chip *chip, size_t it, uint32_t type,
		       uint32_t prio);
static void plic_op_enable(struct itr_chip *chip, size_t it);
static void plic_op_disable(struct itr_chip *chip, size_t it);
static void plic_op_raise_pi(struct itr_chip *chip, size_t it);
static void plic_op_raise_sgi(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask);
static void plic_op_set_affinity(struct itr_chip *chip, size_t it,
			uint8_t cpu_mask);

static const struct itr_ops plic_ops = {
	.add = plic_op_add,
	.enable = plic_op_enable,
	.disable = plic_op_disable,
	.raise_pi = plic_op_raise_pi,
	.raise_sgi = plic_op_raise_sgi,
	.set_affinity = plic_op_set_affinity,
};

static void plic_op_add(struct itr_chip *chip, size_t it,
		       uint32_t type __unused,
		       uint32_t prio __unused)
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

static void plic_op_raise_sgi(struct itr_chip *chip __unused, size_t it __unused,
			uint8_t cpu_mask __unused)
{
}

static void plic_op_set_affinity(struct itr_chip *chip __unused, size_t it __unused,
			uint8_t cpu_mask __unused)
{
}

static int plic_dt_get_irq(const uint32_t *properties __unused, int count __unused, uint32_t *type __unused,
			  uint32_t *prio __unused)
{
	return DT_INFO_INVALID_INTERRUPT;
}

static size_t probe_max_it(vaddr_t plic_base __unused)
{
	return PLIC_NUM_SOURCES;
}

void plic_init_base_addr(struct plic_data *pd,
			paddr_t plic_base_pa __maybe_unused)
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

void plic_hart_init(struct plic_data *gd __unused)
{	
}

void plic_init(struct plic_data *pd, paddr_t plic_base_pa)
{
	size_t n;

	plic_init_base_addr(pd, plic_base_pa);

	for (n = 0; n <= pd->max_it; n++) {
		plic_disable_interrupt(pd, n);
		plic_set_priority(pd, n, 1);
	}

	plic_set_threshold(pd, 0);
}

void plic_it_handle(struct plic_data *pd)
{
	uint32_t id;

	id = plic_claim_interrupt(pd);

	if (id <= pd->max_it)
		itr_handle(id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);

	plic_complete_interrupt(pd, id);
}
