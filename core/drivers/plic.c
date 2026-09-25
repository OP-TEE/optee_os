// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023,2026 NXP
 */

#include <assert.h>
#include <config.h>
#include <drivers/plic.h>
#include <encoding.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/misc_arch.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <libfdt.h>
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
#define PLIC_ENABLE(base, source, context) \
		((base) + PLIC_ENABLE_OFFSET + \
		SHIFT_U32(context, PLIC_ENABLE_SHIFT_PER_TARGET) +\
		(4 * ((source) / 32)) \
	)
#define PLIC_THRESHOLD(base, context) \
		((base) + PLIC_THRESHOLD_OFFSET + \
		SHIFT_U32(context, PLIC_THRESHOLD_SHIFT_PER_TARGET) \
	)
#define PLIC_COMPLETE(base, context) \
		((base) + PLIC_CLAIM_OFFSET + \
		SHIFT_U32(context, PLIC_CLAIM_SHIFT_PER_TARGET) \
	)
#define PLIC_CLAIM(base, context) PLIC_COMPLETE(base, context)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PLIC_BASE, PLIC_REG_SIZE);

#define PLIC_CONTEXT_INVALID		UINT32_MAX

struct plic_data {
	vaddr_t plic_base;
	size_t max_it;
	/* Context of the hart at each entry of hartids[] */
	uint32_t hart_context[CFG_TEE_CORE_NB_CORE];
	/* Context of the hart at each core position, set at hart init */
	uint32_t context[CFG_TEE_CORE_NB_CORE];
	struct itr_chip chip;
};

static struct plic_data plic_data __nex_bss;

static uint32_t plic_get_context(void)
{
	uint32_t context = plic_data.context[get_core_pos()];

	assert(context != PLIC_CONTEXT_INVALID);

	return context;
}

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
	uint32_t context = plic_get_context();

	io_setbits32(PLIC_ENABLE(pd->plic_base, source, context),
		     BIT(source & 0x1f));
}

static uint32_t __maybe_unused
plic_get_interrupt_enable(struct plic_data *pd, uint32_t source)
{
	uint32_t context = plic_get_context();

	return io_read32(PLIC_ENABLE(pd->plic_base, source, context)) &
	       BIT(source & 0x1f);
}

static void plic_disable_interrupt(struct plic_data *pd, uint32_t source)
{
	uint32_t context = plic_get_context();

	io_clrbits32(PLIC_ENABLE(pd->plic_base, source, context),
		     BIT(source & 0x1f));
}

static uint32_t __maybe_unused plic_get_threshold(struct plic_data *pd)
{
	uint32_t context = plic_get_context();

	return io_read32(PLIC_THRESHOLD(pd->plic_base, context));
}

static void plic_set_threshold(struct plic_data *pd, uint32_t threshold)
{
	uint32_t context = plic_get_context();

	io_write32(PLIC_THRESHOLD(pd->plic_base, context), threshold);
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
	uint32_t context = plic_get_context();

	return io_read32(PLIC_CLAIM(pd->plic_base, context));
}

static void plic_complete_interrupt(struct plic_data *pd, uint32_t source)
{
	uint32_t context = plic_get_context();

	io_write32(PLIC_CLAIM(pd->plic_base, context), source);
}

static void plic_op_configure(struct itr_chip *chip, size_t it,
			      uint32_t type __unused, uint32_t prio)
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
			      size_t it __unused, uint32_t cpu_mask __unused)
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
	.configure = plic_op_configure,
	.mask = plic_op_disable,
	.unmask = plic_op_enable,
	.enable = plic_op_enable,
	.disable = plic_op_disable,
	.raise_pi = plic_op_raise_pi,
	.raise_sgi = plic_op_raise_sgi,
	.set_affinity = plic_op_set_affinity,
};

static void plic_init_base_addr(struct plic_data *pd, paddr_t plic_base_pa)
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

/*
 * The PLIC node lists its contexts in "interrupts-extended", one
 * <phandle irq> pair per context in context order, the phandle being the
 * interrupt controller of a hart. The context of a hart is the index of
 * the pair naming its interrupt controller with the external interrupt
 * of the privilege mode OP-TEE runs in.
 */
static bool plic_dt_context(const void *fdt, int node, uint32_t hartid,
			    uint32_t *context)
{
	uint32_t irq = IS_ENABLED(CFG_RISCV_M_MODE) ? IRQ_M_EXT : IRQ_S_EXT;
	const fdt32_t *prop = NULL;
	uint32_t phandle = 0;
	uint32_t reg = 0;
	int intc = 0;
	int cpu = 0;
	int len = 0;
	int n = 0;

	prop = fdt_getprop(fdt, node, "interrupts-extended", &len);
	if (!prop)
		return false;
	len /= sizeof(*prop);

	for (n = 0; n + 1 < len; n += 2) {
		phandle = fdt32_to_cpu(prop[n]);
		/* An absent context is <0xffffffff> */
		if (phandle == UINT32_MAX || fdt32_to_cpu(prop[n + 1]) != irq)
			continue;

		intc = fdt_node_offset_by_phandle(fdt, phandle);
		if (intc < 0)
			continue;

		cpu = fdt_parent_offset(fdt, intc);
		if (cpu < 0 || fdt_read_uint32(fdt, cpu, "reg", &reg))
			continue;

		if (reg == hartid) {
			*context = n / 2;
			return true;
		}
	}

	return false;
}

/* The PLIC node is the one whose "reg" is the base we were given */
static int plic_dt_node(const void *fdt, paddr_t plic_base_pa)
{
	static const char * const compatible[] = {
		"riscv,plic0",
		"sifive,plic-1.0.0",
		"thead,c900-plic",
	};
	paddr_t base = 0;
	size_t size = 0;
	size_t i = 0;
	int node = 0;

	for (i = 0; i < ARRAY_SIZE(compatible); i++) {
		node = fdt_node_offset_by_compatible(fdt, -1, compatible[i]);
		while (node >= 0) {
			if (!fdt_reg_info(fdt, node, &base, &size) &&
			    base == plic_base_pa)
				return node;

			node = fdt_node_offset_by_compatible(fdt, node,
							     compatible[i]);
		}
	}

	return -1;
}

/*
 * Without a device tree, the contexts are assumed to be laid out with an
 * M-mode and an S-mode context per hart, in hart ID order:
 * PLIC context 0 is hart 0 M-mode
 * PLIC context 1 is hart 0 S-mode
 * PLIC context 2 is hart 1 M-mode
 * PLIC context 3 is hart 1 S-mode
 * ...
 */
static uint32_t plic_default_context(uint32_t hartid)
{
	return hartid * 2 + IS_ENABLED(CFG_RISCV_S_MODE);
}

static void plic_init_hart_contexts(struct plic_data *pd,
				    paddr_t plic_base_pa)
{
	const void *fdt = NULL;
	int node = -1;
	size_t n = 0;

	if (IS_ENABLED(CFG_DT))
		fdt = get_dt();
	if (fdt)
		node = plic_dt_node(fdt, plic_base_pa);
	if (node < 0)
		DMSG("No PLIC node in device tree, assuming default contexts");

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		pd->context[n] = PLIC_CONTEXT_INVALID;
		pd->hart_context[n] = PLIC_CONTEXT_INVALID;
		if (n >= hartids_count)
			continue;

		if (node < 0)
			pd->hart_context[n] = plic_default_context(hartids[n]);
		else if (!plic_dt_context(fdt, node, hartids[n],
					  &pd->hart_context[n]))
			EMSG("No PLIC context for hart%"PRIu32, hartids[n]);
	}
}

/* Set the context of the calling hart, then quiesce it */
static void plic_init_per_hart(struct plic_data *pd)
{
	uint32_t context = PLIC_CONTEXT_INVALID;
	uint32_t hartid = thread_get_hartid();
	size_t n = 0;

	for (n = 0; n < hartids_count; n++) {
		if (hartids[n] == hartid) {
			context = pd->hart_context[n];
			break;
		}
	}

	if (context == PLIC_CONTEXT_INVALID) {
		EMSG("hart%"PRIu32" has no PLIC context", hartid);
		panic();
	}
	pd->context[get_core_pos()] = context;

	for (n = 0; n <= pd->max_it; n++)
		plic_disable_interrupt(pd, n);

	plic_set_threshold(pd, 0);
}

void plic_hart_init(void)
{
	plic_init_per_hart(&plic_data);
}

void plic_init(paddr_t plic_base_pa)
{
	struct plic_data *pd = &plic_data;
	size_t n = 0;

	plic_init_base_addr(pd, plic_base_pa);
	plic_init_hart_contexts(pd, plic_base_pa);
	plic_init_per_hart(pd);

	for (n = 0; n <= pd->max_it; n++)
		plic_set_priority(pd, n, 1);

	interrupt_main_init(&plic_data.chip);
}

void plic_it_handle(void)
{
	struct plic_data *pd = &plic_data;
	uint32_t id = plic_claim_interrupt(pd);

	if (id > 0 && id <= pd->max_it)
		interrupt_call_handlers(&pd->chip, id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);

	plic_complete_interrupt(pd, id);
}
