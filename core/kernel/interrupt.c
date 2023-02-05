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

static struct itr_chip *itr_main_chip __nex_bss;
static SLIST_HEAD(, itr_handler) handlers __nex_data =
	SLIST_HEAD_INITIALIZER(handlers);

TEE_Result itr_chip_init(struct itr_chip *chip)
{
	if (!itr_chip_is_valid(chip))
		return TEE_ERROR_BAD_PARAMETERS;

	SLIST_INIT(&chip->handlers);

	return TEE_SUCCESS;
}

void interrupt_main_init(struct itr_chip *chip)
{
	assert(itr_chip_is_valid(chip));
	itr_main_chip = chip;
}

struct itr_chip *interrupt_get_main_chip(void)
{
	assert(itr_main_chip);
	return itr_main_chip;
}

#ifdef CFG_DT
int dt_get_irq_type_prio(const void *fdt, int node, uint32_t *type,
			 uint32_t *prio)
{
	const uint32_t *prop = NULL;
	int count = 0;
	int it_num = DT_INFO_INVALID_INTERRUPT;

	if (!itr_main_chip || !itr_main_chip->dt_get_irq)
		return it_num;

	prop = fdt_getprop(fdt, node, "interrupts", &count);
	if (!prop)
		return it_num;

	return itr_main_chip->dt_get_irq(prop, count, type, prio);
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
		itr_main_chip->ops->disable(itr_main_chip, it);
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

	itr_main_chip->ops->disable(itr_main_chip, hdl->it);

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

	itr_main_chip->ops->add(itr_main_chip, h->it, type, prio);
	SLIST_INSERT_HEAD(&handlers, h, link);
}

void itr_enable(size_t it)
{
	itr_main_chip->ops->enable(itr_main_chip, it);
}

void itr_disable(size_t it)
{
	itr_main_chip->ops->disable(itr_main_chip, it);
}

void itr_raise_pi(size_t it)
{
	itr_main_chip->ops->raise_pi(itr_main_chip, it);
}

void itr_raise_sgi(size_t it, uint8_t cpu_mask)
{
	itr_main_chip->ops->raise_sgi(itr_main_chip, it, cpu_mask);
}

void itr_set_affinity(size_t it, uint8_t cpu_mask)
{
	itr_main_chip->ops->set_affinity(itr_main_chip, it, cpu_mask);
}

/* This function is supposed to be overridden in platform specific code */
void __weak __noreturn interrupt_main_handler(void)
{
	panic("Secure interrupt handler not defined");
}

/*
 * Interrupt controller chip support
 */
void interrupt_call_handlers(struct itr_chip *chip, size_t itr_num)
{
	struct itr_handler *h = NULL;
	bool was_handled = false;

	assert(chip);

	SLIST_FOREACH(h, &chip->handlers, link) {
		if (h->it == itr_num) {
			if (h->handler(h) == ITRR_HANDLED)
				was_handled = true;
			else if (!(h->flags & ITRF_SHARED))
				break;
		}
	}

	if (!was_handled) {
		EMSG("Disable unhandled interrupt %s:%zu", chip->name, itr_num);
		interrupt_disable(chip, itr_num);
	}
}

TEE_Result interrupt_configure(struct itr_chip *chip, size_t itr_num,
			       uint32_t type, uint32_t prio)
{
	chip->ops->add(chip, itr_num, type, prio);

	return TEE_SUCCESS;
}

TEE_Result interrupt_add_handler(struct itr_handler *hdl)
{
	struct itr_handler *h = NULL;

	assert(hdl && hdl->chip->ops);

	SLIST_FOREACH(h, &hdl->chip->handlers, link)
		if (h->it == hdl->it &&
		    (!(hdl->flags & ITRF_SHARED) || !(h->flags & ITRF_SHARED)))
			return TEE_ERROR_GENERIC;

	interrupt_configure(hdl->chip, hdl->it, IRQ_TYPE_NONE, 0);

	SLIST_INSERT_HEAD(&hdl->chip->handlers, hdl, link);

	return TEE_SUCCESS;
}

void interrupt_remove_handler(struct itr_handler *hdl)
{
	struct itr_handler *h = NULL;
	bool disable_itr = true;

	if (!hdl)
		return;

	SLIST_FOREACH(h, &hdl->chip->handlers, link)
		if (h == hdl)
			break;
	if (!h) {
		DMSG("Invalid %s:%zu", hdl->chip->name, hdl->it);
		assert(false);
		return;
	}

	if (hdl->flags & ITRF_SHARED) {
		SLIST_FOREACH(h, &hdl->chip->handlers, link) {
			if (h != hdl && h->it == hdl->it) {
				disable_itr = false;
				break;
			}
		}
	}

	if (disable_itr)
		interrupt_disable(hdl->chip, hdl->it);

	SLIST_REMOVE(&hdl->chip->handlers, hdl, itr_handler, link);
}

TEE_Result interrupt_alloc_add_handler(struct itr_chip *chip, size_t itr_num,
				       itr_handler_t handler, uint32_t flags,
				       void *data, struct itr_handler **out_hdl)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct itr_handler *hdl = NULL;

	hdl = calloc(1, sizeof(*hdl));
	if (!hdl)
		return TEE_ERROR_OUT_OF_MEMORY;

	*hdl = (struct itr_handler){
		.chip = chip,
		.it = itr_num,
		.handler = handler,
		.flags = flags,
		.data = data,
	};

	res = interrupt_add_handler(hdl);
	if (res) {
		free(hdl);
		return res;
	}

	if (out_hdl)
		*out_hdl = hdl;

	return TEE_SUCCESS;
}

void interrupt_remove_free_handler(struct itr_handler *hdl)
{
	if (hdl) {
		interrupt_remove_handler(hdl);
		free(hdl);
	}
}

#ifdef CFG_DT
TEE_Result dt_register_interrupt_provider(const void *fdt, int node,
					  dt_get_itr_func dt_get_itr,
					  void *data)
{
	return dt_driver_register_provider(fdt, node,
					   (get_of_device_func)dt_get_itr,
					   data, DT_DRIVER_INTERRUPT);
}

/*
 * Provide an itr_desc reference based on "interrupts" property bindings.
 * May return TEE_ERROR_DEFER_DRIVER_INIT if parent controller is found but
 * not yet initialized.
 */
static TEE_Result get_legacy_interrupt_by_index(const void *fdt, int node,
						unsigned int index,
						struct itr_desc **desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint32_t *prop = NULL;
	uint32_t phandle = 0;
	int pnode = 0;
	int len = 0;

	prop = fdt_getprop(fdt, node, "interrupts", &len);
	if (!prop)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Find "interrupt-parent" in node or its parents */
	pnode = node;
	prop = fdt_getprop(fdt, pnode, "interrupt-parent", &len);

	while (!prop) {
		pnode = fdt_parent_offset(fdt, pnode);
		if (pnode < 0)
			break;

		prop = fdt_getprop(fdt, pnode, "interrupt-parent", &len);
		if (!prop && len != -FDT_ERR_NOTFOUND)
			break;
	}
	if (!prop) {
		DMSG("No interrupt parent for node %s",
		     fdt_get_name(fdt, node, NULL));
		return TEE_ERROR_GENERIC;
	}

	/* "interrupt-parent" provides interrupt controller phandle */
	phandle = fdt32_to_cpu(prop[0]);

	/* Get interrupt chip/number from phandle and "interrupts" property */
	*desc = dt_driver_device_from_node_idx_prop_phandle("interrupts", fdt,
							    node, index,
							    DT_DRIVER_INTERRUPT,
							    phandle, &res);
	return res;
}

/*
 * Provide an itr_desc based on "interrupts-extended" property bindings.
 * May return TEE_ERROR_DEFER_DRIVER_INIT if parent controller is found
 * but not yet initialized.
 * With this function, provider is expected to have allocated itr_desc
 * with malloc() or like.
 */
static TEE_Result get_extended_interrupt_by_index(const void *fdt, int node,
						  unsigned int index,
						  struct itr_desc **desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	*desc = dt_driver_device_from_node_idx_prop("interrupts-extended",
						    fdt, node, index,
						    DT_DRIVER_INTERRUPT, &res);

	return res;
}

TEE_Result dt_get_interrupt_by_index(const void *fdt, int node,
				     unsigned int index, struct itr_chip **chip,
				     size_t *itr_num)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct itr_desc *desc = NULL;

	assert(chip && itr_num);

	/* "interrupts-extended" takes precedence over "interrupts" */
	if (fdt_getprop(fdt, node, "interrupts-extended", NULL))
		res = get_extended_interrupt_by_index(fdt, node, index, &desc);
	else
		res = get_legacy_interrupt_by_index(fdt, node, index, &desc);

	assert((!res && desc) || (res && !desc));

	if (!res) {
		*chip = desc->chip;
		*itr_num = desc->itr_num;

		/* Balance malloc() or like from dt_get_itr_func callback */
		free(desc);
	}

	return res;
}

TEE_Result dt_get_interrupt_by_name(const void *fdt, int node, const char *name,
				    struct itr_chip **chip, size_t *itr_num)
{
	int idx = 0;

	idx = fdt_stringlist_search(fdt, node, "interrupt-names", name);
	if (idx < 0)
		return TEE_ERROR_GENERIC;

	return dt_get_interrupt_by_index(fdt, node, idx, chip, itr_num);
}
#endif /*CFG_DT*/
