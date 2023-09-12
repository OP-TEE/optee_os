// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Microchip.
 */
#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/pinctrl.h>
#include <initcall.h>
#include <io.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <malloc.h>
#include <matrix.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#define PIO_GROUP_COUNT		4
#define PIO_GROUP_OFFSET	0x40
#define PIO_REG(reg, group)	((reg) + ((group) * PIO_GROUP_OFFSET))
/* Mask register */
#define PIO_MSKR(group)		PIO_REG(0x0, (group))
/* Configuration register */
#define PIO_CFGR(group)		PIO_REG(0x4, (group))
#define PIO_CFGR_FUNC		GENMASK(2, 0)
#define PIO_CFGR_PUEN		BIT(9)
#define PIO_CFGR_PDEN		BIT(10)

/* Non-Secure configuration register */
#define PIO_SIONR(group)	PIO_REG(0x30, (group))
/* Secure configuration register */
#define PIO_SIOSR(group)	PIO_REG(0x34, (group))

#define DT_GET_PIN_NO(val)	((val) & 0xFF)
#define DT_GET_FUNC(val)	(((val) >> 16) & 0xF)

struct atmel_pio {
	vaddr_t base;
};

struct atmel_pio_pin_conf {
	uint32_t pin_mask;
	uint32_t pin_cfg;
	uint8_t pio_group;
	struct atmel_pio *pio;
};

static void pio_write(struct atmel_pio *pio, unsigned int offset, uint32_t val)
{
	io_write32(pio->base + offset, val);
}

static TEE_Result pio_conf_apply(struct pinconf *conf)
{
	struct atmel_pio_pin_conf *pio_conf = conf->priv;
	struct atmel_pio *pio = pio_conf->pio;

	DMSG("Apply cfg %#" PRIx32 " on group %" PRIu8 ", pins %#" PRIx32,
	     pio_conf->pin_cfg, pio_conf->pio_group, pio_conf->pin_mask);

	pio_write(pio, PIO_SIOSR(pio_conf->pio_group), pio_conf->pin_mask);
	pio_write(pio, PIO_MSKR(pio_conf->pio_group), pio_conf->pin_mask);
	pio_write(pio, PIO_CFGR(pio_conf->pio_group), pio_conf->pin_cfg);

	return TEE_SUCCESS;
}

static void pio_conf_free(struct pinconf *conf)
{
	free(conf);
}

static const struct pinctrl_ops pio_pinctrl_ops = {
	.conf_apply = pio_conf_apply,
	.conf_free = pio_conf_free,
};

static TEE_Result pio_pinctrl_dt_get(struct dt_pargs *pargs, void *data,
				     struct pinconf **out_pinconf)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int i = 0;
	int func = 0;
	int group = 0;
	int pin_no = 0;
	uint32_t cfg = 0;
	int prop_count = 0;
	int pio_group = -1;
	uint32_t pinmux = 0;
	uint32_t pin_mask = 0;
	bitstr_t *cfg_modes = NULL;
	const uint32_t *prop = NULL;
	struct pinconf *pinconf = NULL;
	struct atmel_pio *atmel_pio = data;
	struct atmel_pio_pin_conf *pio_conf = NULL;

	prop = fdt_getprop(pargs->fdt, pargs->phandle_node, "pinmux",
			   &prop_count);
	if (!prop)
		return TEE_ERROR_ITEM_NOT_FOUND;

	prop_count /= sizeof(uint32_t);
	for (i = 0; i < prop_count; i++) {
		pinmux = fdt32_to_cpu(prop[i]);

		pin_no = DT_GET_PIN_NO(pinmux);
		func = DT_GET_FUNC(pinmux);

		group = pin_no / 32;
		if (pio_group == -1) {
			pio_group = group;
		} else {
			if (group != pio_group) {
				EMSG("Unexpected group %d vs %d", group,
				     pio_group);
				return TEE_ERROR_GENERIC;
			}
		}

		pin_mask |= BIT(pin_no % 32);
	}

	cfg = func;

	res = pinctrl_parse_dt_pin_modes(pargs->fdt, pargs->phandle_node,
					 &cfg_modes);
	if (res)
		return res;

	for (i = 0; i < PINCTRL_DT_PROP_MAX; i++) {
		if (!bit_test(cfg_modes, i))
			continue;

		switch (i) {
		case PINCTRL_DT_PROP_BIAS_PULL_UP:
			cfg |= PIO_CFGR_PUEN;
			cfg &= ~PIO_CFGR_PDEN;
			break;
		case PINCTRL_DT_PROP_BIAS_PULL_DOWN:
			cfg |= PIO_CFGR_PDEN;
			cfg &= ~PIO_CFGR_PUEN;
			break;
		case PINCTRL_DT_PROP_BIAS_DISABLE:
			break;
		default:
			EMSG("Unhandled config %u", i);
			break;
		}
	}

	free(cfg_modes);

	pinconf = calloc(1, sizeof(*pinconf) + sizeof(*pio_conf));
	if (!pinconf)
		return TEE_ERROR_OUT_OF_MEMORY;

	pio_conf = (struct atmel_pio_pin_conf *)(pinconf + 1);

	pio_conf->pin_mask = pin_mask;
	pio_conf->pin_cfg = cfg;
	pio_conf->pio = atmel_pio;
	pio_conf->pio_group = pio_group;
	pinconf->priv = pio_conf;
	pinconf->ops = &pio_pinctrl_ops;

	*out_pinconf = pinconf;

	return TEE_SUCCESS;
}

static void pio_init_hw(struct atmel_pio *pio)
{
	int i = 0;

	/* Set all IOs as non-secure */
	for (i = 0; i < PIO_GROUP_COUNT; i++)
		pio_write(pio, PIO_SIONR(PIO_GROUP_COUNT), GENMASK_32(31, 0));
}

/* Non-null reference for compat data */
static const uint8_t has_pioe;

static TEE_Result pio_node_probe(const void *fdt, int node,
				 const void *compat_data)
{
	size_t size = 0;
	struct clk *clk = NULL;
	struct atmel_pio *pio = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_BAD_STATE;

	pio = calloc(1, sizeof(*pio));
	if (!pio)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = clk_dt_get_by_index(fdt, node, 0, &clk);
	if (res)
		goto free_pio;

	if (dt_map_dev(fdt, node, &pio->base, &size, DT_MAP_AUTO) < 0)
		goto free_pio;

	res = clk_enable(clk);
	if (res)
		goto free_pio;

	matrix_configure_periph_secure(AT91C_ID_PIOA);
	matrix_configure_periph_secure(AT91C_ID_PIOB);
	matrix_configure_periph_secure(AT91C_ID_PIOC);
	matrix_configure_periph_secure(AT91C_ID_PIOD);

	if (compat_data == &has_pioe)
		matrix_configure_periph_secure(AT91C_ID_PIOD + 1);

	pio_init_hw(pio);

	res = pinctrl_register_provider(fdt, node, pio_pinctrl_dt_get, pio);
	if (res)
		goto disable_clock;

	return TEE_SUCCESS;

disable_clock:
	clk_disable(clk);
free_pio:
	free(pio);

	return res;
}

static const struct dt_device_match atmel_pio_match_table[] = {
	{ .compatible = "atmel,sama5d2-pinctrl" },
	{
		.compatible = "microchip,sama7g5-pinctrl",
		.compat_data = &has_pioe,
	},
	{ }
};

DEFINE_DT_DRIVER(atmel_pio_dt_driver) = {
	.name = "atmel_pio",
	.type = DT_DRIVER_PINCTRL,
	.match_table = atmel_pio_match_table,
	.probe = pio_node_probe,
};
