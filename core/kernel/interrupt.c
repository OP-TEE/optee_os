// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2019, Linaro Limited
 */

#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
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

TEE_Result itr_chip_init(struct itr_chip *chip)
{
	if (!itr_chip_is_valid(chip))
		return TEE_ERROR_BAD_PARAMETERS;

	SLIST_INIT(&chip->handlers);

	return TEE_SUCCESS;
}

void interrupt_main_init(struct itr_chip *chip)
{
	if (itr_chip_init(chip))
		panic();

	itr_main_chip = chip;
}

struct itr_chip *interrupt_get_main_chip(void)
{
	assert(itr_main_chip);
	return itr_main_chip;
}

struct itr_chip *interrupt_get_main_chip_may_fail(void)
{
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
		EMSG("Mask unhandled interrupt %s:%zu", chip->name, itr_num);
		interrupt_mask(chip, itr_num);
	}
}

TEE_Result interrupt_configure(struct itr_chip *chip, size_t itr_num,
			       uint32_t type, uint32_t prio)
{
	chip->ops->add(chip, itr_num, type, prio);

	return TEE_SUCCESS;
}

static TEE_Result add_configure_handler(struct itr_handler *hdl,
					uint32_t type, uint32_t prio,
					bool configure)
{
	struct itr_handler *h = NULL;

	assert(hdl && hdl->chip->ops && is_unpaged(hdl) &&
	       hdl->handler && is_unpaged(hdl->handler));

	SLIST_FOREACH(h, &hdl->chip->handlers, link) {
		if (h->it == hdl->it &&
		    (!(hdl->flags & ITRF_SHARED) ||
		     !(h->flags & ITRF_SHARED))) {
			EMSG("Shared and non-shared flags on interrupt %s#%zu",
			     hdl->chip->name, hdl->it);
			return TEE_ERROR_GENERIC;
		}
	}

	if (configure)
		interrupt_configure(hdl->chip, hdl->it, type, prio);

	SLIST_INSERT_HEAD(&hdl->chip->handlers, hdl, link);

	return TEE_SUCCESS;
}

TEE_Result interrupt_add_configure_handler(struct itr_handler *hdl,
					   uint32_t type, uint32_t prio)
{
	return add_configure_handler(hdl, type, prio, true /* configure */);
}

TEE_Result interrupt_create_handler(struct itr_chip *itr_chip, size_t itr_num,
				    itr_handler_t callback, void *priv,
				    uint32_t flags,
				    struct itr_handler **out_hdl)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct itr_handler *itr_hdl = NULL;

	itr_hdl = calloc(1, sizeof(*itr_hdl));
	if (!itr_hdl)
		return TEE_ERROR_OUT_OF_MEMORY;

	*itr_hdl = (struct itr_handler){
		.chip = itr_chip,
		.it = itr_num,
		.flags = flags,
		.handler = callback,
		.data = priv,
	};

	res = add_configure_handler(itr_hdl, 0, 0, false /* configure */);
	if (res) {
		free(itr_hdl);
		return res;
	}

	if (out_hdl)
		*out_hdl = itr_hdl;

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

TEE_Result interrupt_alloc_add_conf_handler(struct itr_chip *chip,
					    size_t itr_num,
					    itr_handler_t handler,
					    uint32_t flags, void *data,
					    uint32_t type, uint32_t prio,
					    struct itr_handler **out_hdl)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct itr_handler *hdl = NULL;

	hdl = calloc(1, sizeof(*hdl));
	if (!hdl)
		return TEE_ERROR_OUT_OF_MEMORY;

	*hdl = ITR_HANDLER(chip, itr_num, flags, handler, data);

	res = interrupt_add_configure_handler(hdl, type, prio);
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
TEE_Result interrupt_register_provider(const void *fdt, int node,
				       itr_dt_get_func dt_get_itr, void *data)
{
	return dt_driver_register_provider(fdt, node,
					   (get_of_device_func)dt_get_itr,
					   data, DT_DRIVER_INTERRUPT);
}

/*
 * Fills an itr_desc reference based on "interrupts" property bindings.
 * May return TEE_ERROR_DEFER_DRIVER_INIT if parent controller is found but
 * not yet initialized.
 */
static TEE_Result get_legacy_interrupt_by_index(const void *fdt, int node,
						unsigned int index,
						struct itr_desc *itr_desc)
{
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
	return dt_driver_device_from_node_idx_prop_phandle("interrupts", fdt,
							   node, index,
							   DT_DRIVER_INTERRUPT,
							   phandle,
							   itr_desc);
}

/*
 * Fills an itr_desc based on "interrupts-extended" property bindings.
 * May return TEE_ERROR_DEFER_DRIVER_INIT if parent controller is found
 * but not yet initialized.
 */
static TEE_Result get_extended_interrupt_by_index(const void *fdt, int node,
						  unsigned int index,
						  struct itr_desc *itr_desc)
{
	return dt_driver_device_from_node_idx_prop("interrupts-extended",
						   fdt, node, index,
						   DT_DRIVER_INTERRUPT,
						   itr_desc);
}

TEE_Result interrupt_dt_get_by_index(const void *fdt, int node,
				     unsigned int index, struct itr_chip **chip,
				     size_t *itr_num)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct itr_desc desc = { };

	assert(chip && itr_num);

	/* "interrupts-extended" takes precedence over "interrupts" */
	if (fdt_getprop(fdt, node, "interrupts-extended", NULL))
		res = get_extended_interrupt_by_index(fdt, node, index, &desc);
	else
		res = get_legacy_interrupt_by_index(fdt, node, index, &desc);

	if (!res) {
		assert(desc.chip);
		*chip = desc.chip;
		*itr_num = desc.itr_num;
	}

	return res;
}

TEE_Result interrupt_dt_get_by_name(const void *fdt, int node, const char *name,
				    struct itr_chip **chip, size_t *itr_num)
{
	int idx = 0;

	idx = fdt_stringlist_search(fdt, node, "interrupt-names", name);
	if (idx < 0)
		return TEE_ERROR_GENERIC;

	return interrupt_dt_get_by_index(fdt, node, idx, chip, itr_num);
}
#endif /*CFG_DT*/
