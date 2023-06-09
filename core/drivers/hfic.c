// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <drivers/hfic.h>
#include <hafnium.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/thread.h>

struct hfic_data {
	struct itr_chip chip;
};

static struct hfic_data hfic_data __nex_bss;

static void hfic_op_add(struct itr_chip *chip __unused, size_t it __unused,
			uint32_t type __unused, uint32_t prio __unused)
{
}

static void hfic_op_enable(struct itr_chip *chip __unused, size_t it)
{
	uint32_t res __maybe_unused = 0;

	res = thread_hvc(HF_INTERRUPT_ENABLE, it, HF_ENABLE,
			 HF_INTERRUPT_TYPE_IRQ);
	assert(!res);
}

static void hfic_op_disable(struct itr_chip *chip __unused, size_t it)
{
	uint32_t res __maybe_unused = 0;

	res = thread_hvc(HF_INTERRUPT_ENABLE, it, HF_DISABLE,
			 HF_INTERRUPT_TYPE_IRQ);
	assert(!res);
}

static void hfic_op_raise_pi(struct itr_chip *chip __unused, size_t it __unused)
{
	panic();
}

static void hfic_op_raise_sgi(struct itr_chip *chip __unused,
			      size_t it __unused, uint8_t cpu_mask __unused)
{
	panic();
}

static void hfic_op_set_affinity(struct itr_chip *chip __unused,
				 size_t it __unused, uint8_t cpu_mask __unused)
{
	panic();
}

static const struct itr_ops hfic_ops = {
	.add = hfic_op_add,
	.mask = hfic_op_disable,
	.unmask = hfic_op_enable,
	.enable = hfic_op_enable,
	.disable = hfic_op_disable,
	.raise_pi = hfic_op_raise_pi,
	.raise_sgi = hfic_op_raise_sgi,
	.set_affinity = hfic_op_set_affinity,
};

void hfic_init(void)
{
	hfic_data.chip.ops = &hfic_ops;
	interrupt_main_init(&hfic_data.chip);
}

/* Override interrupt_main_handler() with driver implementation */
void interrupt_main_handler(void)
{
	uint32_t id = 0;
	uint32_t res __maybe_unused = 0;

	id = thread_hvc(HF_INTERRUPT_GET, 0, 0, 0);
	if (id == HF_INVALID_INTID) {
		DMSG("ignoring invalid interrupt %#"PRIx32, id);
		return;
	}

	itr_handle(id);
	res = thread_hvc(HF_INTERRUPT_DEACTIVATE, id, id, 0);
	assert(!res);
}
