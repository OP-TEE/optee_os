// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2019, Linaro Limited
 */

#include <kernel/interrupt.h>
#include <kernel/panic.h>
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

static __maybe_unused struct itr_handler *find_handler(size_t it)
{
	struct itr_handler *h;

	SLIST_FOREACH(h, &handlers, link)
		if (h->it == it)
			return h;
	return NULL;
}

void itr_handle(size_t it)
{
	struct itr_handler *h = NULL;
	enum itr_return ret = ITRR_NONE;

	SLIST_FOREACH(h, &handlers, link) {

		if (h->it != it)
			continue;

		ret = h->handler(h);

		if (ret == ITRR_NONE) {
			continue;
		} else if (ret == ITRR_HANDLED) {
			return;
		} else {
			EMSG("Disabling interrupt %zu not handled by handler", it);
			itr_chip->ops->disable(itr_chip, it);
			return;
		}
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

/* This function is supposed to be overridden in platform specific code */
void __weak __noreturn itr_core_handler(void)
{
	panic("Secure interrupt handler not defined");
}
