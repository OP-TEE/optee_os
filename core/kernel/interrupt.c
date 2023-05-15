// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2019, Linaro Limited
 */

#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <stdlib.h>
#include <trace.h>
#include <assert.h>

/*
 * NOTE!
 *
 * We're assuming that there's no concurrent use of this interface, except
 * delivery of interrupts in parallel. Synchronization will be needed when
 * we begin to modify settings after boot initialization.
 */

static struct itr_chip *itr_chip __nex_bss;
static SLIST_HEAD(, itr_handler) handlers __nex_data =
	SLIST_HEAD_INITIALIZER(handlers);

void itr_init(struct itr_chip *chip)
{
	itr_chip = chip;
}

#ifdef CFG_DT
int dt_get_irq_type_prio(const void *fdt, int node, uint32_t *type,
			 uint32_t *prio)
{
	const uint32_t *prop = NULL;
	int count = 0;
	int it_num = DT_INFO_INVALID_INTERRUPT;

	if (!itr_chip || !itr_chip->dt_get_irq)
		return it_num;

	prop = fdt_getprop(fdt, node, "interrupts", &count);
	if (!prop)
		return it_num;

	return itr_chip->dt_get_irq(prop, count, type, prio);
}
#endif

void itr_handle(size_t it)
{
	struct itr_handler *h = NULL;
	bool was_handled = false;

	SLIST_FOREACH(h, &handlers, link) {
		if (h->it == it) {
			if (h->handler(h) == ITRR_HANDLED)
				was_handled = true;
			else if (!(h->flags & ITRF_SHARED))
				break;
		}
	}

	if (!was_handled) {
		EMSG("Disabling unhandled interrupt %zu", it);
		itr_chip->ops->disable(itr_chip, it);
	}
}

struct itr_handler *itr_alloc_add_type_prio(size_t it, itr_handler_t handler,
					    uint32_t flags, void *data,
					    uint32_t type, uint32_t prio)
{
	struct itr_handler *hdl = calloc(1, sizeof(*hdl));

	if (hdl) {
		hdl->it = it;
		hdl->handler = handler;
		hdl->flags = flags;
		hdl->data = data;
		itr_add_type_prio(hdl, type, prio);
	}

	return hdl;
}

void itr_free(struct itr_handler *hdl)
{
	if (!hdl)
		return;

	itr_chip->ops->disable(itr_chip, hdl->it);

	SLIST_REMOVE(&handlers, hdl, itr_handler, link);
	free(hdl);
}

void itr_add_type_prio(struct itr_handler *h, uint32_t type, uint32_t prio)
{
	struct itr_handler __maybe_unused *hdl = NULL;

	SLIST_FOREACH(hdl, &handlers, link)
		if (hdl->it == h->it)
			assert((hdl->flags & ITRF_SHARED) &&
			       (h->flags & ITRF_SHARED));

	itr_chip->ops->add(itr_chip, h->it, type, prio);
	SLIST_INSERT_HEAD(&handlers, h, link);
}

void itr_enable(size_t it)
{
	itr_chip->ops->enable(itr_chip, it);
}

void itr_disable(size_t it)
{
	itr_chip->ops->disable(itr_chip, it);
}

void itr_raise_pi(size_t it)
{
	itr_chip->ops->raise_pi(itr_chip, it);
}

void itr_raise_sgi(size_t it, uint8_t cpu_mask)
{
	itr_chip->ops->raise_sgi(itr_chip, it, cpu_mask);
}

void itr_set_affinity(size_t it, uint8_t cpu_mask)
{
	itr_chip->ops->set_affinity(itr_chip, it, cpu_mask);
}

/* This function is supposed to be overridden in platform specific code */
void __weak __noreturn itr_core_handler(void)
{
	panic("Secure interrupt handler not defined");
}
