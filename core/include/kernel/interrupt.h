/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2019, Linaro Limited
 */
#ifndef __KERNEL_INTERRUPT_H
#define __KERNEL_INTERRUPT_H

#include <dt-bindings/interrupt-controller/irq.h>
#include <kernel/dt_driver.h>
#include <mm/core_memprot.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define ITRF_TRIGGER_LEVEL	BIT(0)
#define ITRF_SHARED		BIT(1)

/* Forward the interrupt only to the current CPU */
#define ITR_CPU_MASK_TO_THIS_CPU	BIT(31)
/* Forward the interrupt to all CPUs except the current CPU */
#define ITR_CPU_MASK_TO_OTHER_CPUS	BIT(30)

struct itr_handler;

/*
 * struct itr_chip - Interrupt controller
 *
 * @ops Operation callback functions
 * @name Controller name, for debug purpose
 * @handlers Registered handlers list head
 * @dt_get_irq Device tree node parsing function
 */
struct itr_chip {
	const struct itr_ops *ops;
	const char *name;
	SLIST_HEAD(, itr_handler) handlers;
	/*
	 * dt_get_irq - parse a device tree interrupt property
	 *
	 * @properties raw interrupt property from device tree
	 * @count number of elements in @properties
	 * @type If not NULL, output interrupt type (IRQ_TYPE_* defines)
	 * or IRQ_TYPE_NONE if unknown
	 * @prio If not NULL, output interrupt priority value or 0 if unknown
	 */
	int (*dt_get_irq)(const uint32_t *properties, int count, uint32_t *type,
			  uint32_t *prio);
};

/*
 * struct itr_ops - Interrupt controller operations
 * @add		Register and configure an interrupt
 * @enable	Enable an interrupt
 * @disable	Disable an interrupt
 * @mask	Mask an interrupt, may be called from an interrupt context
 * @unmask	Unmask an interrupt, may be called from an interrupt context
 * @raise_pi	Raise per-cpu interrupt or NULL if not applicable
 * @raise_sgi	Raise a SGI or NULL if not applicable to that controller
 * @set_affinity Set interrupt/cpu affinity or NULL if not applicable
 *
 * Handlers @enable, @disable, @mask, @unmask and @add are mandated. Handlers
 * @mask and @unmask have unpaged memory contrainsts. See itr_chip_is_valid().
 */
struct itr_ops {
	void (*add)(struct itr_chip *chip, size_t it, uint32_t type,
		    uint32_t prio);
	void (*enable)(struct itr_chip *chip, size_t it);
	void (*disable)(struct itr_chip *chip, size_t it);
	void (*mask)(struct itr_chip *chip, size_t it);
	void (*unmask)(struct itr_chip *chip, size_t it);
	void (*raise_pi)(struct itr_chip *chip, size_t it);
	void (*raise_sgi)(struct itr_chip *chip, size_t it,
			  uint32_t cpu_mask);
	void (*set_affinity)(struct itr_chip *chip, size_t it,
		uint8_t cpu_mask);
};

/*
 * struct itr_desc - Interrupt description
 * @chip	Interrupt controller reference
 * @itr_num	Interrupt number
 *
 * This struct is used for binding interrupt device data between
 * drivers when using DT_DRIVERS means. See itr_dt_get_func type
 * definition.
 */
struct itr_desc {
	struct itr_chip *chip;
	size_t itr_num;
};

/* Interrupt handler return value */
enum itr_return {
	ITRR_NONE,
	ITRR_HANDLED,
};

/* Interrupt handler signature */
typedef enum itr_return (*itr_handler_t)(struct itr_handler *h);

/*
 * struct itr_handler - Interrupt handler reference
 * @it Interrupt number
 * @flags Property bit flags (ITRF_*) or 0
 * @data Private data for that interrupt handler
 * @chip Interrupt controller chip device
 * @link Reference in controller handler list
 */
struct itr_handler {
	size_t it;
	uint32_t flags;
	itr_handler_t handler;
	void *data;
	struct itr_chip *chip;
	SLIST_ENTRY(itr_handler) link;
};

#define ITR_HANDLER(_chip, _itr_num, _flags, _fn, _priv) \
	((struct itr_handler){ \
		.chip = (_chip), .it = (_itr_num), .flags = (_flags), \
		.handler = (_fn), .data = (_priv), \
	})

/*
 * Return true only if interrupt chip provides required handlers
 * @chip: Interrupt controller reference
 */
static inline bool itr_chip_is_valid(struct itr_chip *chip)
{
	return chip && is_unpaged(chip) && chip->ops &&
	       is_unpaged((void *)chip->ops) &&
	       chip->ops->mask && is_unpaged(chip->ops->mask) &&
	       chip->ops->unmask && is_unpaged(chip->ops->unmask) &&
	       chip->ops->enable && chip->ops->disable &&
	       chip->ops->add;
}

/*
 * Initialise an interrupt controller handle
 * @chip	Interrupt controller
 */
TEE_Result itr_chip_init(struct itr_chip *chip);

/*
 * Initialise main interrupt controller driver
 * @data Main controller main data reference to register
 */
void interrupt_main_init(struct itr_chip *data);

/* Retrieve main interrupt controller reference */
struct itr_chip *interrupt_get_main_chip(void);
/* Retrieve main interrupt controller reference, or NULL on failure */
struct itr_chip *interrupt_get_main_chip_may_fail(void);

#ifdef CFG_DT
/*
 * Get the DT interrupt property at @node. In the DT an interrupt property can
 * specify additional information which can be retrieved with @type and @prio.
 *
 * @fdt reference to the Device Tree
 * @node is the node offset to read the interrupt property from
 * @type interrupt type (IRQ_TYPE_* defines) if specified by interrupt property
 * or IRQ_TYPE_NONE if not. Can be NULL if not needed
 * @prio interrupt priority if specified by interrupt property or 0 if not. Can
 * be NULL if not needed
 *
 * Returns the interrupt number if value >= 0
 * otherwise DT_INFO_INVALID_INTERRUPT
 */
int dt_get_irq_type_prio(const void *fdt, int node, uint32_t *type,
			 uint32_t *prio);

/*
 * Get the DT interrupt property at @node
 */
static inline int dt_get_irq(const void *fdt, int node)
{
	return dt_get_irq_type_prio(fdt, node, NULL, NULL);
}
#endif

/*
 * __weak overridable function which is called when a secure interrupt is
 * received. The default function calls panic() immediately, platforms which
 * expects to receive secure interrupts should override this function.
 */
void interrupt_main_handler(void);

/*
 * Interrupt controller chip API functions
 */

/*
 * interrupt_call_handlers() - Call registered handlers for an interrupt
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 *
 * This function is called from an interrupt context by a primary interrupt
 * handler. This function calls the handlers registered for that interrupt.
 * If interrupt is not handled, it is masked.
 */
void interrupt_call_handlers(struct itr_chip *chip, size_t itr_num);

/*
 * interrupt_mask() - Mask an interrupt
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 *
 * This function may be called in interrupt context
 */
static inline void interrupt_mask(struct itr_chip *chip, size_t itr_num)
{
	chip->ops->mask(chip, itr_num);
}

/*
 * interrupt_unmask() - Unmask an interrupt
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 *
 * This function may be called in interrupt context
 */
static inline void interrupt_unmask(struct itr_chip *chip, size_t itr_num)
{
	chip->ops->unmask(chip, itr_num);
}

/*
 * interrupt_enable() - Enable an interrupt
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 */
static inline void interrupt_enable(struct itr_chip *chip, size_t itr_num)
{
	chip->ops->enable(chip, itr_num);
}

/*
 * interrupt_disable() - Disable an interrupt
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 */
static inline void interrupt_disable(struct itr_chip *chip, size_t itr_num)
{
	chip->ops->disable(chip, itr_num);
}

/*
 * interrupt_can_raise_pi() - Return whether controller embeds raise_pi
 * @chip	Interrupt controller
 */
static inline bool interrupt_can_raise_pi(struct itr_chip *chip)
{
	return chip->ops->raise_pi;
}

/*
 * interrupt_can_raise_sgi() - Return whether controller embeds raise_sgi
 * @chip	Interrupt controller
 */
static inline bool interrupt_can_raise_sgi(struct itr_chip *chip)
{
	return chip->ops->raise_sgi;
}

/*
 * interrupt_can_set_affinity() - Return whether controller embeds set_affinity
 * @chip	Interrupt controller
 */
static inline bool interrupt_can_set_affinity(struct itr_chip *chip)
{
	return chip->ops->set_affinity;
}

/*
 * interrupt_raise_pi() - Raise a peripheral interrupt of a controller
 * @chip	Interrupt controller
 * @itr_num	Interrupt number to raise
 */
static inline void interrupt_raise_pi(struct itr_chip *chip, size_t itr_num)
{
	assert(interrupt_can_raise_pi(chip));
	chip->ops->raise_pi(chip, itr_num);
}

/*
 * interrupt_raise_sgi() - Raise a software generiated interrupt of a controller
 * @chip	Interrupt controller
 * @itr_num	Interrupt number to raise
 * @cpu_mask:	A bitfield of CPUs to forward the interrupt to, unless
 *		ITR_CPU_MASK_TO_THIS_CPU or ITR_CPU_MASK_TO_OTHER_CPUS
 *		(mutually exclusive) are set.
 */
static inline void interrupt_raise_sgi(struct itr_chip *chip, size_t itr_num,
				       uint32_t cpu_mask)
{
	assert(interrupt_can_raise_sgi(chip));
	chip->ops->raise_sgi(chip, itr_num, cpu_mask);
}

/*
 * interrupt_set_affinity() - Set CPU affinity for a controller interrupt
 * @chip	Interrupt controller
 * @itr_num	Interrupt number to raise
 * @cpu_mask	Mask of the CPUs targeted by the interrupt
 */
static inline void interrupt_set_affinity(struct itr_chip *chip, size_t itr_num,
					  uint8_t cpu_mask)
{
	assert(interrupt_can_set_affinity(chip));
	chip->ops->set_affinity(chip, itr_num, cpu_mask);
}

/*
 * interrupt_configure() - Configure an interrupt in an interrupt controller
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 * @type	Interrupt trigger type (IRQ_TYPE_* defines) or IRQ_TYPE_NONE
 * @prio	Interrupt priority or 0
 *
 * Interrupt consumers that get their interrupt from the DT do not need to
 * call interrupt_configure() since the interrupt configuration has already
 * been done by interrupt controller based on the DT bidings.
 */
TEE_Result interrupt_configure(struct itr_chip *chip, size_t itr_num,
			       uint32_t type, uint32_t prio);

/*
 * interrupt_add_and_configure_handler() - Register and configure a handler
 * @hdl		Interrupt handler to register
 * @type	Interrupt trigger type (IRQ_TYPE_* defines) or IRQ_TYPE_NONE
 * @prio	Interrupt priority or 0
 */
TEE_Result interrupt_add_configure_handler(struct itr_handler *hdl,
					   uint32_t type, uint32_t prio);

/*
 * interrupt_add_handler() - Register an interrupt handler
 * @hdl		Interrupt handler to register
 *
 * This helper function assumes interrupt type is set to IRQ_TYPE_NONE
 * and interrupt priority to 0.
 */
static inline TEE_Result interrupt_add_handler(struct itr_handler *hdl)
{
	return interrupt_add_configure_handler(hdl, IRQ_TYPE_NONE, 0);
}

/*
 * interrupt_create_handler() - Allocate/register an interrupt callback handler
 * @itr_chip Interrupt chip obtained from dt_get_interrupt_by_*()
 * @itr_num Interrupt number obtained from dt_get_interrupt_by_*()
 * @callback Callback handler function
 * @priv Private dat to pssa to @callback
 * @flags INTERRUPT_FLAGS_* or 0
 * @out_hdl Output allocated and registered handler or NULL
 *
 * This function  differs from interrupt_add_handler() in that the
 * interrupt is not reconfigured. interrupt_create_handler() expects
 * @itr_desc was obtained from a call to dt_get_interrupt_by_index()
 * or dt_get_interrupt_by_name(). That call configured the interrupt.
 */
TEE_Result interrupt_create_handler(struct itr_chip *itr_chip, size_t itr_num,
				    itr_handler_t callback, void *priv,
				    uint32_t flags,
				    struct itr_handler **out_hdl);

/*
 * interrupt_add_handler_with_chip() - Register an interrupt handler providing
 *	the interrupt chip reference in specific argument @chip.
 * @chip	Interrupt controller
 * @h		Interrupt handler to register
 */
static inline TEE_Result interrupt_add_handler_with_chip(struct itr_chip *chip,
							 struct itr_handler *h)
{
	h->chip = chip;
	return interrupt_add_handler(h);
}

/*
 * interrupt_remove_handler() - Remove a registered interrupt handler
 * @hdl		Interrupt handler to remove
 *
 * This function is the counterpart of interrupt_add_handler().
 * This function may panic on non-NULL invalid @hdl reference.
 */
void interrupt_remove_handler(struct itr_handler *hdl);

/*
 * interrupt_alloc_add_conf_handler() - Allocate, configure, register a handler
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 * @handler	Interrupt handler to register
 * @flags	Bitmask flag ITRF_*
 * @data	Private data reference passed to @handler
 * @type	Interrupt trigger type (IRQ_TYPE_* defines) or IRQ_TYPE_NONE
 * @prio	Interrupt priority or 0
 * @out_hdl	NULL or output pointer to allocated struct itr_handler
 */
TEE_Result interrupt_alloc_add_conf_handler(struct itr_chip *chip,
					    size_t it_num,
					    itr_handler_t handler,
					    uint32_t flags, void *data,
					    uint32_t type, uint32_t prio,
					    struct itr_handler **out_hdl);

/*
 * interrupt_alloc_add_handler() - Allocate and register an interrupt handler
 * @chip	Interrupt controller
 * @itr_num	Interrupt number
 * @handler	Interrupt handler to register
 * @flags	Bitmask flag ITRF_*
 * @data	Private data reference passed to @handler
 * @out_hdl	NULL or output pointer to allocated struct itr_handler
 */
static inline TEE_Result interrupt_alloc_add_handler(struct itr_chip *chip,
						     size_t it_num,
						     itr_handler_t handler,
						     uint32_t flags,
						     void *data,
						     struct itr_handler **hdl)
{
	return interrupt_alloc_add_conf_handler(chip, it_num, handler, flags,
						data, IRQ_TYPE_NONE, 0, hdl);
}

/*
 * interrupt_remove_free_handler() - Remove/free a registered interrupt handler
 * @hdl		Interrupt handler to remove and free
 *
 * This function is the counterpart of interrupt_alloc_add_handler()
 * and interrupt_alloc_add_conf_handler().
 * This function may panic on non-NULL invalid @hdl reference.
 */
void interrupt_remove_free_handler(struct itr_handler *hdl);

/*
 * itr_dt_get_func - Typedef of function to get an interrupt in DT node
 *
 * @args	Reference to phandle arguments
 * @data	Pointer to data given at interrupt_register_provider() call
 * @itr_desc_p	Pointer to the struct itr_desc to fill
 * Return TEE_SUCCESS in case of success.
 * Return TEE_ERROR_DEFER_DRIVER_INIT if controller is not initialized.
 * Return another TEE_Result code otherwise.
 *
 * Upon success, the interrupt is configured and consumer can add a handler
 * function to the interrupt. Yet, the interrupt is not enabled until consumer
 * calls interrupt_enable().
 */
typedef TEE_Result (*itr_dt_get_func)(struct dt_pargs *args, void *data,
				      struct itr_desc *itr_desc_p);

#ifdef CFG_DT
/**
 * interrupt_register_provider() - Register an interrupt provider
 *
 * @fdt		Device tree to work on
 * @node	Node offset of the interrupt controller in the DT
 * @dt_get_itr	Callback to match the devicetree interrupt reference with
 * @data	Data which will be passed to the get_dt_its callback
 */
TEE_Result interrupt_register_provider(const void *fdt, int node,
				       itr_dt_get_func dt_get_itr, void *data);

/**
 * interrupt_dt_get_by_index() - Get an interrupt from DT by interrupt index
 *
 * Interrupt index (@index) refers to the index of the target interrupt to be
 * retrieved as DT binding property "interrupts" may define several
 * interrupts.
 *
 * @fdt		Device tree to work on
 * @node	Node offset of the subnode containing interrupt(s) references
 * @index	Index in "interrupts" or "extended-interrupts" property list
 * @chip	Output interrupt controller reference upon success
 * @itr_num	Output interrupt number upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if interrupt driver is not yet initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the DT does not reference target interrupt
 * Return any other TEE_Result compliant code in case of error
 */
TEE_Result interrupt_dt_get_by_index(const void *fdt, int node,
				     unsigned int index, struct itr_chip **chip,
				     size_t *itr_num);

/**
 * interrupt_dt_get_by_name() - Get an interrupt from DT by interrupt name
 *
 * @fdt		Device tree to work on
 * @node	Node offset of the subnode containing interrupt(s) references
 * @name	Name identifier used in "interrupt-names" property
 * @chip	Output interrupt controller reference upon success
 * @itr_num	Output interrupt number upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if interrupt driver is not yet initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the DT does not reference target interrupt
 * Return any other TEE_Result compliant code in case of error
 */
TEE_Result interrupt_dt_get_by_name(const void *fdt, int node, const char *name,
				    struct itr_chip **chip, size_t *itr_num);
#else
static inline TEE_Result interrupt_register_provider(const void *dt __unused,
						     int node __unused,
						     itr_dt_get_func f __unused,
						     void *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result interrupt_dt_get_by_index(const void *fdt __unused,
						   int node __unused,
						   unsigned int index __unused,
						   struct itr_chip **c __unused,
						   size_t *itr_num __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result interrupt_dt_get_by_name(const void *fdt __unused,
						  int node __unused,
						  const char *name __unused,
						  struct itr_chip **ch __unused,
						  size_t *itr_num __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*CFG_DT*/

/*
 * Helper function for when caller retrieves the first interrupt defined
 * in "interrupts" or "extended-interrupts" DT binding property list.
 */
static inline TEE_Result interrupt_dt_get(const void *fdt, int node,
					  struct itr_chip **chip,
					  size_t *itr_num)
{
	return interrupt_dt_get_by_index(fdt, node, 0, chip, itr_num);
}
#endif /*__KERNEL_INTERRUPT_H*/
