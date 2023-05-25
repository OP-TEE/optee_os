// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 *
 * STM32 GPIO driver is used as pin controller for stm32mp SoCs.
 * The driver API is defined in header file stm32_gpio.h.
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_gpio.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <sys/queue.h>
#include <trace.h>
#include <util.h>

#define GPIO_PIN_MAX		15

#define GPIO_MODER_OFFSET	0x00
#define GPIO_OTYPER_OFFSET	0x04
#define GPIO_OSPEEDR_OFFSET	0x08
#define GPIO_PUPDR_OFFSET	0x0c
#define GPIO_IDR_OFFSET		0x10
#define GPIO_ODR_OFFSET		0x14
#define GPIO_BSRR_OFFSET	0x18
#define GPIO_AFRL_OFFSET	0x20
#define GPIO_AFRH_OFFSET	0x24
#define GPIO_SECR_OFFSET	0x30

#define GPIO_ALT_LOWER_LIMIT	0x8

#define GPIO_MODE_MASK		GENMASK_32(1, 0)
#define GPIO_OSPEED_MASK	GENMASK_32(1, 0)
#define GPIO_PUPD_PULL_MASK	GENMASK_32(1, 0)
#define GPIO_ALTERNATE_MASK	GENMASK_32(3, 0)

#define DT_GPIO_BANK_SHIFT	12
#define DT_GPIO_BANK_MASK	GENMASK_32(16, 12)
#define DT_GPIO_PIN_SHIFT	8
#define DT_GPIO_PIN_MASK	GENMASK_32(11, 8)
#define DT_GPIO_MODE_MASK	GENMASK_32(7, 0)

#define DT_GPIO_BANK_NAME0	"GPIOA"

/**
 * struct stm32_gpio_bank - GPIO bank instance
 *
 * @base: base address of the GPIO controller registers.
 * @clock: clock identifier.
 * @ngpios: number of GPIOs.
 * @bank_id: Id of the bank.
 * @lock: lock protecting the GPIO bank access.
 * @sec_support: True if bank supports pin security protection, otherwise false
 * @seccfgr: Secure configuration register value.
 * @link: Link in bank list
 */
struct stm32_gpio_bank {
	vaddr_t base;
	struct clk *clock;
	unsigned int ngpios;
	unsigned int bank_id;
	unsigned int lock;
	STAILQ_ENTRY(stm32_gpio_bank) link;
};

static unsigned int gpio_lock;

static STAILQ_HEAD(, stm32_gpio_bank) bank_list =
		STAILQ_HEAD_INITIALIZER(bank_list);

static struct stm32_gpio_bank *stm32_gpio_get_bank(unsigned int bank_id)
{
	struct stm32_gpio_bank *bank = NULL;

	STAILQ_FOREACH(bank, &bank_list, link)
		if (bank_id == bank->bank_id)
			return bank;

	panic();
}

/* Save to output @cfg the current GPIO (@bank_id/@pin) configuration */
static void get_gpio_cfg(uint32_t bank_id, uint32_t pin, struct gpio_cfg *cfg)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);

	if (clk_enable(bank->clock))
		panic();

	/*
	 * Save GPIO configuration bits spread over the few bank registers.
	 * 1bit fields are accessed at bit position being the pin index.
	 * 2bit fields are accessed at bit position being twice the pin index.
	 * 4bit fields are accessed at bit position being fourth the pin index
	 * but accessed from 2 32bit registers at incremental addresses.
	 */
	cfg->mode = (io_read32(bank->base + GPIO_MODER_OFFSET) >> (pin << 1)) &
		    GPIO_MODE_MASK;

	cfg->otype = (io_read32(bank->base + GPIO_OTYPER_OFFSET) >> pin) & 1;

	cfg->ospeed = (io_read32(bank->base +  GPIO_OSPEEDR_OFFSET) >>
		       (pin << 1)) & GPIO_OSPEED_MASK;

	cfg->pupd = (io_read32(bank->base +  GPIO_PUPDR_OFFSET) >> (pin << 1)) &
		    GPIO_PUPD_PULL_MASK;

	cfg->od = (io_read32(bank->base + GPIO_ODR_OFFSET) >> (pin << 1)) & 1;

	if (pin < GPIO_ALT_LOWER_LIMIT)
		cfg->af = (io_read32(bank->base + GPIO_AFRL_OFFSET) >>
			   (pin << 2)) & GPIO_ALTERNATE_MASK;
	else
		cfg->af = (io_read32(bank->base + GPIO_AFRH_OFFSET) >>
			   ((pin - GPIO_ALT_LOWER_LIMIT) << 2)) &
			  GPIO_ALTERNATE_MASK;

	clk_disable(bank->clock);
}

/* Apply GPIO (@bank/@pin) configuration described by @cfg */
static void set_gpio_cfg(uint32_t bank_id, uint32_t pin, struct gpio_cfg *cfg)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);
	uint32_t exceptions = cpu_spin_lock_xsave(&gpio_lock);

	if (clk_enable(bank->clock))
		panic();

	/* Load GPIO MODE value, 2bit value shifted by twice the pin number */
	io_clrsetbits32(bank->base + GPIO_MODER_OFFSET,
			GPIO_MODE_MASK << (pin << 1),
			cfg->mode << (pin << 1));

	/* Load GPIO Output TYPE value, 1bit shifted by pin number value */
	io_clrsetbits32(bank->base + GPIO_OTYPER_OFFSET, BIT(pin),
			cfg->otype << pin);

	/* Load GPIO Output Speed confguration, 2bit value */
	io_clrsetbits32(bank->base + GPIO_OSPEEDR_OFFSET,
			GPIO_OSPEED_MASK << (pin << 1),
			cfg->ospeed << (pin << 1));

	/* Load GPIO pull configuration, 2bit value */
	io_clrsetbits32(bank->base + GPIO_PUPDR_OFFSET, BIT(pin),
			cfg->pupd << (pin << 1));

	/* Load pin mux Alternate Function configuration, 4bit value */
	if (pin < GPIO_ALT_LOWER_LIMIT) {
		io_clrsetbits32(bank->base + GPIO_AFRL_OFFSET,
				GPIO_ALTERNATE_MASK << (pin << 2),
				cfg->af << (pin << 2));
	} else {
		size_t shift = (pin - GPIO_ALT_LOWER_LIMIT) << 2;

		io_clrsetbits32(bank->base + GPIO_AFRH_OFFSET,
				GPIO_ALTERNATE_MASK << shift,
				cfg->af << shift);
	}

	/* Load GPIO Output direction confuguration, 1bit */
	io_clrsetbits32(bank->base + GPIO_ODR_OFFSET, BIT(pin), cfg->od << pin);

	clk_disable(bank->clock);
	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
}

void stm32_pinctrl_load_active_cfg(struct stm32_pinctrl *pinctrl, size_t cnt)
{
	size_t n = 0;

	for (n = 0; n < cnt; n++)
		set_gpio_cfg(pinctrl[n].bank, pinctrl[n].pin,
			     &pinctrl[n].active_cfg);
}

void stm32_pinctrl_load_standby_cfg(struct stm32_pinctrl *pinctrl, size_t cnt)
{
	size_t n = 0;

	for (n = 0; n < cnt; n++)
		set_gpio_cfg(pinctrl[n].bank, pinctrl[n].pin,
			     &pinctrl[n].standby_cfg);
}

void stm32_pinctrl_store_standby_cfg(struct stm32_pinctrl *pinctrl, size_t cnt)
{
	size_t n = 0;

	for (n = 0; n < cnt; n++)
		get_gpio_cfg(pinctrl[n].bank, pinctrl[n].pin,
			     &pinctrl[n].standby_cfg);
}

/* Panic if GPIO bank information from platform do not match DTB description */
static void ckeck_gpio_bank(void *fdt, uint32_t bank, int pinctrl_node)
{
	int pinctrl_subnode = 0;

	fdt_for_each_subnode(pinctrl_subnode, fdt, pinctrl_node) {
		const fdt32_t *cuint = NULL;

		if (fdt_getprop(fdt, pinctrl_subnode,
				"gpio-controller", NULL) == NULL)
			continue;

		/* Check bank register offset matches platform assumptions */
		cuint = fdt_getprop(fdt, pinctrl_subnode, "reg", NULL);
		if (fdt32_to_cpu(*cuint) != stm32_get_gpio_bank_offset(bank))
			continue;

		/* Check controller is enabled */
		if (fdt_get_status(fdt, pinctrl_subnode) == DT_STATUS_DISABLED)
			panic();

		return;
	}

	panic();
}

/* Count pins described in the DT node and get related data if possible */
static int get_pinctrl_from_fdt(void *fdt, int node,
				struct stm32_pinctrl *pinctrl, size_t count)
{
	const fdt32_t *cuint, *slewrate;
	int len = 0;
	int pinctrl_node = 0;
	uint32_t i = 0;
	uint32_t speed = GPIO_OSPEED_LOW;
	uint32_t pull = GPIO_PUPD_NO_PULL;
	size_t found = 0;

	cuint = fdt_getprop(fdt, node, "pinmux", &len);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	pinctrl_node = fdt_parent_offset(fdt, fdt_parent_offset(fdt, node));
	if (pinctrl_node < 0)
		return -FDT_ERR_NOTFOUND;

	slewrate = fdt_getprop(fdt, node, "slew-rate", NULL);
	if (slewrate)
		speed = fdt32_to_cpu(*slewrate);

	if (fdt_getprop(fdt, node, "bias-pull-up", NULL))
		pull = GPIO_PUPD_PULL_UP;
	if (fdt_getprop(fdt, node, "bias-pull-down", NULL))
		pull = GPIO_PUPD_PULL_DOWN;

	for (i = 0; i < ((uint32_t)len / sizeof(uint32_t)); i++) {
		uint32_t pincfg = 0;
		uint32_t bank = 0;
		uint32_t pin = 0;
		uint32_t mode = 0;
		uint32_t alternate = 0;
		bool opendrain = false;

		pincfg = fdt32_to_cpu(*cuint);
		cuint++;

		bank = (pincfg & DT_GPIO_BANK_MASK) >> DT_GPIO_BANK_SHIFT;

		pin = (pincfg & DT_GPIO_PIN_MASK) >> DT_GPIO_PIN_SHIFT;

		mode = pincfg & DT_GPIO_MODE_MASK;

		switch (mode) {
		case 0:
			mode = GPIO_MODE_INPUT;
			break;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
		case 16:
			alternate = mode - 1U;
			mode = GPIO_MODE_ALTERNATE;
			break;
		case 17:
			mode = GPIO_MODE_ANALOG;
			break;
		default:
			mode = GPIO_MODE_OUTPUT;
			break;
		}

		if (fdt_getprop(fdt, node, "drive-open-drain", NULL))
			opendrain = true;

		/* Check GPIO bank clock/base address against platform */
		ckeck_gpio_bank(fdt, bank, pinctrl_node);

		if (found < count) {
			struct stm32_pinctrl *ref = &pinctrl[found];

			ref->bank = (uint8_t)bank;
			ref->pin = (uint8_t)pin;
			ref->active_cfg.mode = mode;
			ref->active_cfg.otype = opendrain ? 1 : 0;
			ref->active_cfg.ospeed = speed;
			ref->active_cfg.pupd = pull;
			ref->active_cfg.od = 0;
			ref->active_cfg.af = alternate;
			/* Default to analog mode for standby state */
			ref->standby_cfg.mode = GPIO_MODE_ANALOG;
			ref->standby_cfg.pupd = GPIO_PUPD_NO_PULL;
		}

		found++;
	}

	return (int)found;
}

/* Get bank ID from bank node property st,bank-name or panic on failure */
static unsigned int dt_get_bank_id(const void *fdt, int node)
{
	const int dt_name_len = strlen(DT_GPIO_BANK_NAME0);
	const fdt32_t *cuint = NULL;
	int len = 0;

	/* Parse "st,bank-name" to get its id (eg: GPIOA -> 0) */
	cuint = fdt_getprop(fdt, node, "st,bank-name", &len);
	if (!cuint || (len != dt_name_len + 1))
		panic("Missing/wrong st,bank-name property");

	if (strncmp((const char *)cuint, DT_GPIO_BANK_NAME0, dt_name_len - 1) ||
	    strcmp((const char *)cuint, DT_GPIO_BANK_NAME0) < 0)
		panic("Wrong st,bank-name property");

	return (unsigned int)strcmp((const char *)cuint, DT_GPIO_BANK_NAME0);
}

/*
 * Return whether or not the GPIO bank related to a DT node is already
 * registered in the GPIO bank link.
 */
static bool bank_is_registered(const void *fdt, int node)
{
	unsigned int bank_id = dt_get_bank_id(fdt, node);
	struct stm32_gpio_bank *bank = NULL;

	STAILQ_FOREACH(bank, &bank_list, link)
		if (bank->bank_id == bank_id)
			return true;

	return false;
}

/* Get GPIO bank information from the DT */
static TEE_Result dt_stm32_gpio_bank(const void *fdt, int node,
				     const void *compat_data __unused,
				     int range_offset,
				     struct stm32_gpio_bank **out_bank)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_gpio_bank *bank = NULL;
	const fdt32_t *cuint = NULL;
	struct io_pa_va pa_va = { };
	struct clk *clk = NULL;
	size_t blen = 0;
	paddr_t pa = 0;
	int len = 0;
	int i = 0;

	assert(out_bank);

	/* Probe deferrable devices first */
	res = clk_dt_get_by_index(fdt, node, 0, &clk);
	if (res)
		return res;

	bank = calloc(1, sizeof(*bank));
	if (!bank)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Do not rely *only* on the "reg" property to get the address,
	 * but consider also the "ranges" translation property
	 */
	pa = fdt_reg_base_address(fdt, node);
	if (pa == DT_INFO_INVALID_REG)
		panic("missing reg property");

	pa_va.pa = pa + range_offset;

	blen = fdt_reg_size(fdt, node);
	if (blen == DT_INFO_INVALID_REG_SIZE)
		panic("missing reg size property");

	DMSG("Bank name %s", fdt_get_name(fdt, node, NULL));
	bank->base = io_pa_or_va_secure(&pa_va, blen);
	bank->bank_id = dt_get_bank_id(fdt, node);
	bank->clock = clk;

	/* Parse gpio-ranges with its 4 parameters */
	cuint = fdt_getprop(fdt, node, "gpio-ranges", &len);
	len /= sizeof(*cuint);
	if (len % 4)
		panic("wrong gpio-ranges syntax");

	/* Get the last defined gpio line (offset + nb of pins) */
	for (i = 0; i < len / 4; i++) {
		bank->ngpios = MAX(bank->ngpios,
				   (unsigned int)(fdt32_to_cpu(*(cuint + 1)) +
						  fdt32_to_cpu(*(cuint + 3))));
		cuint += 4;
	}

	*out_bank = bank;
	return TEE_SUCCESS;
}

/* Parse a pinctrl node to register the GPIO banks it describes */
static TEE_Result dt_stm32_gpio_pinctrl(const void *fdt, int node,
					const void *compat_data)
{
	TEE_Result res = TEE_SUCCESS;
	const fdt32_t *cuint = NULL;
	int range_offs = 0;
	int b_node = 0;
	int len = 0;

	/* Read the ranges property (for regs memory translation) */
	cuint = fdt_getprop(fdt, node, "ranges", &len);
	if (!cuint)
		panic("missing ranges property");

	len /= sizeof(*cuint);
	if (len == 3)
		range_offs = fdt32_to_cpu(*(cuint + 1)) - fdt32_to_cpu(*cuint);

	fdt_for_each_subnode(b_node, fdt, node) {
		cuint = fdt_getprop(fdt, b_node, "gpio-controller", &len);
		if (cuint) {
			/*
			 * We found a property "gpio-controller" in the node:
			 * the node is a GPIO bank description, add it to the
			 * bank list.
			 */
			struct stm32_gpio_bank *bank = NULL;

			if (fdt_get_status(fdt, b_node) == DT_STATUS_DISABLED ||
			    bank_is_registered(fdt, b_node))
				continue;

			res = dt_stm32_gpio_bank(fdt, b_node, compat_data,
						 range_offs, &bank);
			if (res)
				return res;

			STAILQ_INSERT_TAIL(&bank_list, bank, link);
		} else {
			if (len != -FDT_ERR_NOTFOUND)
				panic();
		}
	}

	return TEE_SUCCESS;
}

int stm32_pinctrl_fdt_get_pinctrl(void *fdt, int device_node,
				  struct stm32_pinctrl *pinctrl, size_t count)
{
	const fdt32_t *cuint = NULL;
	int lenp = 0;
	int i = 0;
	size_t found = 0;

	cuint = fdt_getprop(fdt, device_node, "pinctrl-0", &lenp);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	for (i = 0; i < (lenp / 4); i++) {
		int node = 0;
		int subnode = 0;

		node = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
		if (node < 0)
			return -FDT_ERR_NOTFOUND;

		fdt_for_each_subnode(subnode, fdt, node) {
			size_t n = 0;
			int rc = 0;

			if (count > found)
				n = count - found;
			else
				n = 0;

			rc = get_pinctrl_from_fdt(fdt, subnode,
						  &pinctrl[found], n);
			if (rc < 0)
				return rc;

			found += (size_t)rc;
		}

		cuint++;
	}

	return (int)found;
}

int stm32_get_gpio_count(void *fdt, int pinctrl_node, unsigned int bank)
{
	int node = 0;
	const fdt32_t *cuint = NULL;

	fdt_for_each_subnode(node, fdt, pinctrl_node) {
		if (!fdt_getprop(fdt, node, "gpio-controller", NULL))
			continue;

		cuint = fdt_getprop(fdt, node, "reg", NULL);
		if (!cuint)
			continue;

		if (fdt32_to_cpu(*cuint) != stm32_get_gpio_bank_offset(bank))
			continue;

		cuint = fdt_getprop(fdt, node, "ngpios", NULL);
		if (!cuint)
			panic();

		return (int)fdt32_to_cpu(*cuint);
	}

	return -1;
}

static __maybe_unused bool valid_gpio_config(unsigned int bank_id,
					     unsigned int pin, bool input)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);
	uint32_t mode = (io_read32(bank->base + GPIO_MODER_OFFSET) >>
			 (pin << 1)) & GPIO_MODE_MASK;

	if (pin > GPIO_PIN_MAX)
		return false;

	if (input)
		return mode == GPIO_MODE_INPUT;
	else
		return mode == GPIO_MODE_OUTPUT;
}

int stm32_gpio_get_input_level(unsigned int bank_id, unsigned int pin)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);
	int rc = 0;

	if (clk_enable(bank->clock))
		panic();

	assert(valid_gpio_config(bank_id, pin, true));

	if (io_read32(bank->base + GPIO_IDR_OFFSET) == BIT(pin))
		rc = 1;

	clk_disable(bank->clock);

	return rc;
}

void stm32_gpio_set_output_level(unsigned int bank_id, unsigned int pin,
				 int level)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);

	if (clk_enable(bank->clock))
		panic();

	assert(valid_gpio_config(bank_id, pin, false));

	if (level)
		io_write32(bank->base + GPIO_BSRR_OFFSET, BIT(pin));
	else
		io_write32(bank->base + GPIO_BSRR_OFFSET, BIT(pin + 16));

	clk_disable(bank->clock);
}

void stm32_gpio_set_secure_cfg(unsigned int bank_id, unsigned int pin,
			       bool secure)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);
	uint32_t exceptions = cpu_spin_lock_xsave(&gpio_lock);

	if (clk_enable(bank->clock))
		panic();

	if (secure)
		io_setbits32(bank->base + GPIO_SECR_OFFSET, BIT(pin));
	else
		io_clrbits32(bank->base + GPIO_SECR_OFFSET, BIT(pin));

	clk_disable(bank->clock);
	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
}

static TEE_Result stm32_pinctrl_probe(const void *fdt, int node,
				      const void *compat_data)
{
	/* Register GPIO banks described in this pin control node */
	return dt_stm32_gpio_pinctrl(fdt, node, compat_data);
}

static const struct dt_device_match stm32_pinctrl_match_table[] = {
	{ .compatible = "st,stm32mp135-pinctrl" },
	{ .compatible = "st,stm32mp157-pinctrl" },
	{ .compatible = "st,stm32mp157-z-pinctrl" },
	{ }
};

DEFINE_DT_DRIVER(stm32_pinctrl_dt_driver) = {
	.name = "stm32_gpio-pinctrl",
	.type = DT_DRIVER_PINCTRL,
	.match_table = stm32_pinctrl_match_table,
	.probe = stm32_pinctrl_probe,
};
