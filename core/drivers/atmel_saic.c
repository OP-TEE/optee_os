// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <assert.h>
#include <drivers/atmel_saic.h>
#include <dt-bindings/interrupt-controller/irq.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <sam_sfr.h>
#include <tee_api_types.h>
#include <trace.h>

#define AT91_AIC_MAX_PRIO	8

#define SAMA5D2_AIC_MAX_IRQS	77

#define SAMA5D2_AIC_MAX_IRQS32	((SAMA5D2_AIC_MAX_IRQS + 31) / 32)

struct saic_data {
	struct itr_chip chip;
	vaddr_t base;
	size_t nr_irqs;
	uint32_t external[SAMA5D2_AIC_MAX_IRQS32];
};

static struct saic_data saic;

static void saic_register_pm(void);

static void saic_write_reg(uint32_t reg, uint32_t val)
{
	io_write32(saic.base + reg, val);
}

static uint32_t saic_read_reg(uint32_t reg)
{
	return io_read32(saic.base + reg);
}

void interrupt_main_handler(void)
{
	uint32_t irqnr = saic_read_reg(AT91_AIC_IVR);

	interrupt_call_handlers(&saic.chip, irqnr);
	saic_write_reg(AT91_AIC_EOICR, 0);
}

static void saic_select_it(size_t it)
{
	assert(!(it & ~AT91_AIC_SSR_ITSEL_MASK));

	saic_write_reg(AT91_AIC_SSR, it);
}

static void saic_configure_it(size_t it, uint32_t src_type, uint32_t priority)
{
	saic_select_it(it);
	saic_write_reg(AT91_AIC_SMR, src_type | priority);
}

static bool is_external_it(size_t it)
{
	uint32_t it_grp = it / 32;
	uint32_t it_off = it % 32;

	if (it >= saic.nr_irqs)
		panic();

	return saic.external[it_grp] & BIT32(it_off);
}

static TEE_Result saic_get_src_type(uint32_t dt_level, size_t it,
				    uint32_t *src_type)
{
	switch (dt_level) {
	case IRQ_TYPE_EDGE_RISING:
		*src_type = AT91_AIC_SMR_POS_EDGE;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		if (!is_external_it(it))
			return TEE_ERROR_BAD_PARAMETERS;

		*src_type = AT91_AIC_SMR_NEG_EDGE;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		*src_type = AT91_AIC_SMR_HIGH_LEVEL;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		if (!is_external_it(it))
			return TEE_ERROR_BAD_PARAMETERS;

		*src_type = AT91_AIC_SMR_LEVEL;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void saic_add(struct itr_chip *chip __unused, size_t it,
		     uint32_t type, uint32_t prio)
{
	uint32_t src_type = AT91_AIC_SMR_HIGH_LEVEL;

	if (it >= saic.nr_irqs)
		panic();

	if (saic_get_src_type(type, it, &src_type))
		panic("Invalid interrupt specifier");

	saic_configure_it(it, src_type, prio);
}

static void saic_enable(struct itr_chip *chip __unused, size_t it)
{
	saic_select_it(it);
	saic_write_reg(AT91_AIC_IECR, 1);
}

static void saic_disable(struct itr_chip *chip __unused, size_t it)
{
	saic_select_it(it);
	saic_write_reg(AT91_AIC_IDCR, 1);
}

static const struct itr_ops saic_ops = {
	.add = saic_add,
	.mask = saic_disable,
	.unmask = saic_enable,
	.enable = saic_enable,
	.disable = saic_disable,
};

static int saic_dt_get_irq(const uint32_t *properties, int len,
			   uint32_t *type, uint32_t *prio)
{
	int it = DT_INFO_INVALID_INTERRUPT;
	uint32_t src_type = 0;
	uint32_t priority = 0;
	uint32_t irq_type = 0;

	len /= sizeof(uint32_t);

	if (len != 3)
		return DT_INFO_INVALID_INTERRUPT;

	it = fdt32_to_cpu(properties[0]);
	if (it >= (int)saic.nr_irqs)
		return DT_INFO_INVALID_INTERRUPT;

	irq_type = fdt32_to_cpu(properties[1]);
	if (saic_get_src_type(irq_type, it, &src_type))
		return DT_INFO_INVALID_INTERRUPT;

	priority = fdt32_to_cpu(properties[2]);
	if (priority >= AT91_AIC_MAX_PRIO)
		return DT_INFO_INVALID_INTERRUPT;

	if (type)
		*type = irq_type;

	if (prio)
		*prio = priority;

	return it;
}

static struct saic_data saic = {
	.chip = {
		.ops = &saic_ops,
		.dt_get_irq = &saic_dt_get_irq,
	},
};

static void saic_clear_aicredir(void)
{
	vaddr_t sfr_base = sam_sfr_base();
	uint32_t aicredir_val = 0;

	aicredir_val = io_read32(sfr_base + AT91_SFR_SN1);
	aicredir_val ^= AT91_SFR_AICREDIR_XOR_KEY;
	aicredir_val &= AT91_SFR_AICREDIR_KEY_MASK;

	/*
	 * We explicitly don't want to redirect secure interrupts to non secure
	 * AIC. By default, AT91Bootstrap does so on some platforms.
	 */
	io_write32(sfr_base + AT91_SFR_AICREDIR, aicredir_val);
}

static void saic_init_external(const void *fdt, int node)
{
	int i = 0;
	int len = 0;
	int it_grp = 0;
	int it_off = 0;
	size_t it = 0;
	const uint32_t *external = NULL;

	external = fdt_getprop(fdt, node, "atmel,external-irqs", &len);
	if (!external)
		return;

	len /= sizeof(uint32_t);
	for (i = 0; i < len; i++) {
		it = fdt32_to_cpu(external[i]);

		DMSG("IRQ %zu is external", it);

		if (it >= saic.nr_irqs)
			panic();

		it_grp = it / 32;
		it_off = it % 32;

		saic.external[it_grp] |= BIT32(it_off);
	}
}

static void saic_init_hw(void)
{
	unsigned int i = 0;

	saic_clear_aicredir();

	/* Disable write protect if any */
	saic_write_reg(AT91_AIC_WPMR, AT91_AIC_WPKEY);

	/* Pop the (potential) interrupt stack (8 priority) */
	for (i = 0; i < 8; i++)
		saic_write_reg(AT91_AIC_EOICR, 0);

	/* Disable and clear all interrupts initially */
	for (i = 0; i < saic.nr_irqs; i++) {
		saic_write_reg(AT91_AIC_IDCR, 1);
		saic_write_reg(AT91_AIC_ICCR, 1);
		/* Set interrupt vector to hold interrupt number */
		saic_select_it(i);
		saic_write_reg(AT91_AIC_SVR, i);
	}

	saic_write_reg(AT91_AIC_SPU, 0xffffffff);

	/* Disable AIC debugging */
	saic_write_reg(AT91_AIC_DCR, 0);
}

TEE_Result atmel_saic_setup(void)
{
	int node = -1;
	int ret = 0;
	size_t size = 0;
	const void *fdt = get_embedded_dt();

	/* There is only 1 SAIC controller */
	if (saic.base)
		return TEE_ERROR_GENERIC;

	node = fdt_node_offset_by_compatible(fdt, -1, "atmel,sama5d2-saic");
	if (node < 0)
		return TEE_ERROR_GENERIC;

	ret = dt_map_dev(fdt, node, &saic.base, &size, DT_MAP_AUTO);
	if (ret) {
		EMSG("Failed to map SAIC");
		return TEE_ERROR_GENERIC;
	}

	saic.chip.ops = &saic_ops;
	saic.nr_irqs = SAMA5D2_AIC_MAX_IRQS;

	saic_init_external(fdt, node);
	saic_init_hw();

	interrupt_main_init(&saic.chip);
	saic_register_pm();

	return TEE_SUCCESS;
}

#ifdef CFG_PM_ARM32

static struct {
	uint8_t smr[SAMA5D2_AIC_MAX_IRQS];
} saic_state;

static void saic_resume(void)
{
	uint8_t it = 0;

	saic_init_hw();

	for (it = 0; it < SAMA5D2_AIC_MAX_IRQS; it++) {
		saic_select_it(it);
		saic_write_reg(AT91_AIC_SMR, saic_state.smr[it]);
	}
}

static void saic_suspend(void)
{
	uint8_t it = 0;

	for (it = 0; it < SAMA5D2_AIC_MAX_IRQS; it++) {
		saic_select_it(it);
		saic_state.smr[it] = saic_read_reg(AT91_AIC_SMR);
	}
}

static TEE_Result saic_pm(enum pm_op op, uint32_t pm_hint __unused,
			  const struct pm_callback_handle *hdl __unused)
{
	switch (op) {
	case PM_OP_RESUME:
		saic_resume();
		break;
	case PM_OP_SUSPEND:
		saic_suspend();
		break;
	default:
		panic("Invalid PM operation");
	}

	return TEE_SUCCESS;
}

static void saic_register_pm(void)
{
	register_pm_core_service_cb(saic_pm, NULL, "saic");
}
#else
static void saic_register_pm(void)
{
}
#endif
