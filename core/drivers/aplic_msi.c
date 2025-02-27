// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Beijing Institute of Open Source Chip (BOSC)
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <drivers/aplic.h>
#include <drivers/aplic_priv.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

static struct aplic_data aplic_data __nex_bss;

static void aplic_set_target(struct aplic_data *aplic, uint32_t source,
			     uint32_t hart_idx, uint32_t guest_idx,
			     uint32_t eiid)
{
	vaddr_t target = 0;
	uint32_t val = 0;

	val = SHIFT_U32(hart_idx, APLIC_TARGET_HART_IDX_SHIFT) &
		APLIC_TARGET_HART_IDX_MASK;
	val |= SHIFT_U32(guest_idx, APLIC_TARGET_GUEST_IDX_SHIFT) &
		APLIC_TARGET_GUEST_IDX_MASK;
	val |= eiid & APLIC_TARGET_EIID_MASK;

	target = aplic->aplic_base + APLIC_TARGET_BASE +
	    (source - 1) * sizeof(uint32_t);
	io_write32(target, val);
}

static uint32_t __unused aplic_get_source_mode(struct aplic_data *aplic,
					       uint32_t source)
{
	uint32_t sm = 0;

	sm = io_read32(aplic->aplic_base + APLIC_SOURCECFG_BASE +
		       (source - 1) * sizeof(uint32_t));

	return sm & APLIC_SOURCECFG_SM_MASK;
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
	aplic->num_idc = 0;
	aplic->num_source = APLIC_NUM_SOURCE;
}

static void aplic_op_configure(struct itr_chip *chip, size_t it, uint32_t type,
			       uint32_t prio __unused)
{
	struct aplic_data *aplic = container_of(chip, struct aplic_data, chip);
	size_t hartid = get_core_pos();

	if (aplic_is_bad_it(aplic, it))
		panic();

	aplic_disable_interrupt(aplic, it);
	if (aplic_set_source_mode(aplic, it, type))
		panic();

	aplic_set_target(aplic, it, hartid, 0, it);
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

	io_write32(aplic->aplic_base + APLIC_DOMAINCFG,
		   APLIC_DOMAINCFG_IE | APLIC_DOMAINCFG_DM);

	interrupt_main_init(&aplic_data.chip);
}

void aplic_init_per_hart(void)
{
}

void aplic_it_handle(void)
{
}

void aplic_dump_state(void)
{
}
