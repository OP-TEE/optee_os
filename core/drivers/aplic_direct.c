// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Beijing Institute of Open Source Chip (BOSC)
 */

#include <assert.h>
#include <config.h>
#include <drivers/aplic.h>
#include <drivers/aplic_priv.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#define APLIC_MAX_IDC            BIT(14)    /* 16384 */
#define APLIC_IDC_BASE           0x4000
#define APLIC_IDC_SIZE           32

/* Interrupt Delivery Control (IDC) structure */
#define APLIC_IDC_IDELIVERY      0x00
#define APLIC_IDC_IFORCE         0x04
#define APLIC_IDC_ITHRESHOLD     0x08

#define APLIC_IDC_TOPI           0x18
#define APLIC_IDC_TOPI_ID_SHIFT  16
#define APLIC_IDC_TOPI_ID_MASK   GENMASK_32(25, 16)
#define APLIC_IDC_TOPI_PRIO_MASK GENMASK_32(7, 0)

#define APLIC_IDC_CLAIMI         0x1C

#define APLIC_DISABLE_IDELIVERY  0
#define APLIC_ENABLE_IDELIVERY   1

#define APLIC_DISABLE_ITHRESHOLD 1
#define APLIC_ENABLE_ITHRESHOLD  0

static struct aplic_data aplic_data __nex_bss;

static vaddr_t aplic_get_idc_base(void)
{
	struct aplic_data *aplic = &aplic_data;
	size_t hartid = get_core_pos();

	return aplic->aplic_base + APLIC_IDC_BASE + hartid * APLIC_IDC_SIZE;
}

static uint32_t aplic_claim_interrupt(void)
{
	uint32_t id = 0;
	vaddr_t idc_base = aplic_get_idc_base();

	id = io_read32(idc_base + APLIC_IDC_CLAIMI);
	id >>= APLIC_IDC_TOPI_ID_SHIFT;

	return id;
}

static void aplic_set_target(struct aplic_data *aplic, uint32_t source,
			     uint32_t hart_idx, uint32_t iprio)
{
	vaddr_t target = 0;
	uint32_t val = 0;

	val = SHIFT_U32(hart_idx, APLIC_TARGET_HART_IDX_SHIFT) &
		APLIC_TARGET_HART_IDX_MASK;
	val |= iprio & APLIC_TARGET_IPRIO_MASK;

	target = aplic->aplic_base + APLIC_TARGET_BASE +
		(source - 1) * sizeof(uint32_t);
	io_write32(target, val);
}

static void aplic_init_base_addr(struct aplic_data *aplic,
				 paddr_t aplic_base_pa)
{
	vaddr_t aplic_base = 0;

	assert(cpu_mmu_enabled());

	aplic_base = core_mmu_get_va(aplic_base_pa, MEM_AREA_IO_SEC,
				     APLIC_SIZE);
	if (!aplic_base)
		panic();

	aplic->aplic_base = aplic_base;
	aplic->size = APLIC_SIZE;
	aplic->targets_mmode = false;
	aplic->num_idc = APLIC_NUM_IDC;
	aplic->num_source = APLIC_NUM_SOURCE;
}

static void aplic_op_configure(struct itr_chip *chip, size_t it, uint32_t type,
			       uint32_t prio)
{
	struct aplic_data *aplic = container_of(chip, struct aplic_data, chip);
	size_t hartid = get_core_pos();

	if (aplic_is_bad_it(aplic, it))
		panic();

	aplic_disable_interrupt(aplic, it);
	if (aplic_set_source_mode(aplic, it, type))
		panic();
	aplic_set_target(aplic, it, hartid, prio);
}

static void aplic_op_enable(struct itr_chip *chip, size_t it)
{
	struct aplic_data *aplic = container_of(chip, struct aplic_data, chip);

	if (aplic_is_bad_it(aplic, it))
		panic();

	aplic_enable_interrupt(aplic, it);
}

static void aplic_op_disable(struct itr_chip *chip, size_t it)
{
	struct aplic_data *aplic = container_of(chip, struct aplic_data, chip);

	if (aplic_is_bad_it(aplic, it))
		panic();

	aplic_disable_interrupt(aplic, it);
}

static void aplic_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct aplic_data *aplic = container_of(chip, struct aplic_data, chip);

	if (aplic_is_bad_it(aplic, it))
		panic();

	aplic_set_pending(aplic, it);
}

static const struct itr_ops aplic_ops = {
	.configure = aplic_op_configure,
	.enable = aplic_op_enable,
	.disable = aplic_op_disable,
	.mask = aplic_op_disable,
	.unmask = aplic_op_enable,
	.raise_pi = aplic_op_raise_pi,
};

void aplic_init(paddr_t aplic_base_pa)
{
	struct aplic_data *aplic = &aplic_data;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (IS_ENABLED(CFG_DT)) {
		res = aplic_init_from_device_tree(aplic);
		if (res)
			panic();
	} else {
		aplic_init_base_addr(aplic, aplic_base_pa);
	}

	aplic->chip.ops = &aplic_ops;

	aplic_init_per_hart();
	io_write32(aplic->aplic_base + APLIC_DOMAINCFG, APLIC_DOMAINCFG_IE);

	interrupt_main_init(&aplic_data.chip);
}

void aplic_init_per_hart(void)
{
	vaddr_t idc_base = aplic_get_idc_base();

	io_write32(idc_base + APLIC_IDC_IDELIVERY, APLIC_ENABLE_IDELIVERY);
	io_write32(idc_base + APLIC_IDC_ITHRESHOLD, APLIC_ENABLE_ITHRESHOLD);
}

void aplic_it_handle(void)
{
	struct aplic_data *aplic = &aplic_data;
	uint32_t id = aplic_claim_interrupt();

	if (id > 0 && id <= aplic->num_source)
		interrupt_call_handlers(&aplic->chip, id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);
}

void aplic_dump_state(void)
{
}
