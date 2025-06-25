// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <drivers/hfic.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/thread.h>

/*
 * For documentation of the paravirtualized interface see:
 * https://hafnium.readthedocs.io/en/latest/design/secure-partition-manager.html#paravirtualized-interfaces
 */

#define HF_INTERRUPT_ENABLE		0xff03
#define HF_INTERRUPT_GET		0xff04
#define HF_INTERRUPT_DEACTIVATE		0xff08
#define HF_INTERRUPT_RECONFIGURE	0xff09

#define HF_INVALID_INTID		0xffffffff
#define HF_MAILBOX_READABLE_INTID	1
#define HF_MAILBOX_WRITABLE_INTID	2
#define HF_VIRTUAL_TIMER_INTID		3
#define HF_MANAGED_EXIT_INTID		4
#define HF_NOTIFICATION_PENDING_INTID	5
#define HF_IPI_INTID			9

#define HF_INTERRUPT_TYPE_IRQ	0
#define HF_INTERRUPT_TYPE_FIQ	1
#define HF_ENABLE		1
#define HF_DISABLE		0

#define HF_INT_RECONFIGURE_STATUS 2

struct hfic_data {
	struct itr_chip chip;
};

static struct hfic_data hfic_data __nex_bss;

static bool __maybe_unused hfic_static_it(size_t it)
{
	switch (it) {
	case HF_MAILBOX_READABLE_INTID:
	case HF_MAILBOX_WRITABLE_INTID:
	case HF_VIRTUAL_TIMER_INTID:
	case HF_MANAGED_EXIT_INTID:
	case HF_NOTIFICATION_PENDING_INTID:
	case HF_IPI_INTID:
		return true;
	default:
		return false;
	}
}

static void hfic_op_configure(struct itr_chip *chip __unused, size_t it,
			      uint32_t type __unused, uint32_t prio __unused)
{
	uint32_t res __maybe_unused = 0;

	res = thread_hvc(HF_INTERRUPT_ENABLE, it, HF_ENABLE,
			 HF_INTERRUPT_TYPE_IRQ);
	assert(!res || hfic_static_it(it));
}

static void hfic_op_enable(struct itr_chip *chip __unused, size_t it)
{
	uint32_t res __maybe_unused = 0;

	res = thread_hvc(HF_INTERRUPT_RECONFIGURE, it,
			 HF_INT_RECONFIGURE_STATUS, HF_ENABLE);
	assert(!res || hfic_static_it(it));
}

static void hfic_op_disable(struct itr_chip *chip __unused, size_t it)
{
	uint32_t res __maybe_unused = 0;

	res = thread_hvc(HF_INTERRUPT_RECONFIGURE, it,
			 HF_INT_RECONFIGURE_STATUS, HF_DISABLE);
	assert(!res || hfic_static_it(it));
}

static const struct itr_ops hfic_ops = {
	.configure = hfic_op_configure,
	.mask = hfic_op_disable,
	.unmask = hfic_op_enable,
	.enable = hfic_op_enable,
	.disable = hfic_op_disable,
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

	interrupt_call_handlers(&hfic_data.chip, id);

	res = thread_hvc(HF_INTERRUPT_DEACTIVATE, id, id, 0);
	assert(!res);
}
