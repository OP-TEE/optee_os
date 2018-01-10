// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <kernel/interrupt.h>
#include <trace.h>

/*
 * NOTE!
 *
 * We're assuming that there's no concurrent use of this interface, except
 * delivery of interrupts in parallel. Synchronization will be needed when
 * we begin to modify settings after boot initialization.
 */

static struct itr_chip *itr_chip;
static SLIST_HEAD(, itr_handler) handlers = SLIST_HEAD_INITIALIZER(handlers);

void itr_init(struct itr_chip *chip)
{
	itr_chip = chip;
}

static struct itr_handler *find_handler(size_t it)
{
	struct itr_handler *h;

	SLIST_FOREACH(h, &handlers, link)
		if (h->it == it)
			return h;
	return NULL;
}

void itr_handle(size_t it)
{
	struct itr_handler *h = find_handler(it);

	if (!h) {
		EMSG("Disabling unhandled interrupt %zu", it);
		itr_chip->ops->disable(itr_chip, it);
		return;
	}

	if (h->handler(h) != ITRR_HANDLED) {
		EMSG("Disabling interrupt %zu not handled by handler", it);
		itr_chip->ops->disable(itr_chip, it);
	}
}

void itr_add(struct itr_handler *h)
{
	itr_chip->ops->add(itr_chip, h->it, h->flags);
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
