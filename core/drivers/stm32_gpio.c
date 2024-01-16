// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 *
 * STM32 GPIO driver is used as pin controller for stm32mp SoCs.
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/gpio.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_gpio.h>
#include <dt-bindings/gpio/stm32mp_gpio.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>
#include <stm32_util.h>
#include <sys/queue.h>
#include <trace.h>
#include <util.h>

#ifndef CFG_DRIVERS_GPIO
#error stm32_gpio driver expects CFG_DRIVERS_GPIO
#endif

#define GPIO_PIN_MAX		15

#define GPIO_MODER_OFFSET	U(0x00)
#define GPIO_OTYPER_OFFSET	U(0x04)
#define GPIO_OSPEEDR_OFFSET	U(0x08)
#define GPIO_PUPDR_OFFSET	U(0x0c)
#define GPIO_IDR_OFFSET		U(0x10)
#define GPIO_ODR_OFFSET		U(0x14)
#define GPIO_BSRR_OFFSET	U(0x18)
#define GPIO_AFRL_OFFSET	U(0x20)
#define GPIO_AFRH_OFFSET	U(0x24)
#define GPIO_SECR_OFFSET	U(0x30)

#define GPIO_ALT_LOWER_LIMIT	U(0x8)

#define GPIO_MODE_MASK		GENMASK_32(1, 0)
#define GPIO_OSPEED_MASK	GENMASK_32(1, 0)
#define GPIO_PUPD_PULL_MASK	GENMASK_32(1, 0)
#define GPIO_ALTERNATE_MASK	GENMASK_32(3, 0)

#define DT_GPIO_BANK_SHIFT	U(12)
#define DT_GPIO_BANK_MASK	GENMASK_32(16, 12)
#define DT_GPIO_PIN_SHIFT	U(8)
#define DT_GPIO_PIN_MASK	GENMASK_32(11, 8)
#define DT_GPIO_MODE_MASK	GENMASK_32(7, 0)

#define DT_GPIO_BANK_NAME0	"GPIOA"

#define GPIO_MODE_INPUT		U(0x0)
#define GPIO_MODE_OUTPUT	U(0x1)
#define GPIO_MODE_ALTERNATE	U(0x2)
#define GPIO_MODE_ANALOG	U(0x3)

#define GPIO_OTYPE_PUSH_PULL	U(0x0)
#define GPIO_OTYPE_OPEN_DRAIN	U(0x1)

#define GPIO_OSPEED_LOW		U(0x0)
#define GPIO_OSPEED_MEDIUM	U(0x1)
#define GPIO_OSPEED_HIGH	U(0x2)
#define GPIO_OSPEED_VERY_HIGH	U(0x3)

#define GPIO_PUPD_NO_PULL	U(0x0)
#define GPIO_PUPD_PULL_UP	U(0x1)
#define GPIO_PUPD_PULL_DOWN	U(0x2)

#define GPIO_OD_LEVEL_LOW	U(0x0)
#define GPIO_OD_LEVEL_HIGH	U(0x1)

/*
 * GPIO configuration description structured as single 16bit word
 * for efficient save/restore when GPIO pin suspends or resumes.
 *
 * @mode: One of GPIO_MODE_*
 * @otype: One of GPIO_OTYPE_*
 * @ospeed: One of GPIO_OSPEED_*
 * @pupd: One of GPIO_PUPD_*
 * @od: One of GPIO_OD_*
 * @af: Alternate function numerical ID between 0 and 15
 */
struct gpio_cfg {
	uint16_t mode:		2;
	uint16_t otype:		1;
	uint16_t ospeed:	2;
	uint16_t pupd:		2;
	uint16_t od:		1;
	uint16_t af:		4;
};

/*
 * Description of a pin and its muxing
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: Pin number in the GPIO bank
 * @cfg: Pin configuration
 */
struct stm32_pinctrl {
	uint8_t bank;
	uint8_t pin;
	struct gpio_cfg cfg;
};

/*
 * struct stm32_pinctrl_array - Array of pins in a pin control state
 * @count: Number of cells in @pinctrl
 * @pinctrl: Pin control configuration
 */
struct stm32_pinctrl_array {
	size_t count;
	struct stm32_pinctrl pinctrl[];
};

/**
 * struct stm32_gpio_bank - GPIO bank instance
 *
 * @base: base address of the GPIO controller registers.
 * @clock: clock identifier.
 * @gpio_chip: GPIO chip reference for that GPIO bank
 * @ngpios: number of GPIOs.
 * @bank_id: Id of the bank.
 * @lock: lock protecting the GPIO bank access.
 * @sec_support: True if bank supports pin security protection, otherwise false
 * @link: Link in bank list
 */
struct stm32_gpio_bank {
	vaddr_t base;
	struct clk *clock;
	struct gpio_chip gpio_chip;
	unsigned int ngpios;
	unsigned int bank_id;
	unsigned int lock;
	bool sec_support;
	STAILQ_ENTRY(stm32_gpio_bank) link;
};

/**
 * Compatibility information of supported banks
 *
 * @gpioz: True if bank is a GPIOZ bank
 * @secure_control: Identify GPIO security bank capability.
 */
struct bank_compat {
	bool gpioz;
	bool secure_control;
};

static unsigned int gpio_lock;

static STAILQ_HEAD(, stm32_gpio_bank) bank_list =
		STAILQ_HEAD_INITIALIZER(bank_list);

static bool is_stm32_gpio_chip(struct gpio_chip *chip);

static struct stm32_gpio_bank *gpio_chip_to_bank(struct gpio_chip *chip)
{
	return container_of(chip, struct stm32_gpio_bank, gpio_chip);
}

static enum gpio_level stm32_gpio_get_level(struct gpio_chip *chip,
					    unsigned int gpio_pin)
{
	struct stm32_gpio_bank *bank = gpio_chip_to_bank(chip);
	enum gpio_level level = GPIO_LEVEL_HIGH;
	unsigned int reg_offset = 0;
	unsigned int mode = 0;

	assert(gpio_pin < bank->ngpios);

	if (clk_enable(bank->clock))
		panic();

	mode = (io_read32(bank->base + GPIO_MODER_OFFSET) >> (gpio_pin << 1)) &
	       GPIO_MODE_MASK;

	switch (mode) {
	case GPIO_MODE_INPUT:
		reg_offset = GPIO_IDR_OFFSET;
		break;
	case GPIO_MODE_OUTPUT:
		reg_offset = GPIO_ODR_OFFSET;
		break;
	default:
		panic();
	}

	if (io_read32(bank->base + reg_offset) & BIT(gpio_pin))
		level = GPIO_LEVEL_HIGH;
	else
		level = GPIO_LEVEL_LOW;

	clk_disable(bank->clock);

	return level;
}

static void stm32_gpio_set_level(struct gpio_chip *chip, unsigned int gpio_pin,
				 enum gpio_level level)
{
	struct stm32_gpio_bank *bank = gpio_chip_to_bank(chip);

	assert(gpio_pin < bank->ngpios);

	if (clk_enable(bank->clock))
		panic();

	assert(((io_read32(bank->base + GPIO_MODER_OFFSET) >>
		 (gpio_pin << 1)) & GPIO_MODE_MASK) == GPIO_MODE_OUTPUT);

	if (level == GPIO_LEVEL_HIGH)
		io_write32(bank->base + GPIO_BSRR_OFFSET, BIT(gpio_pin));
	else
		io_write32(bank->base + GPIO_BSRR_OFFSET, BIT(gpio_pin + 16));

	clk_disable(bank->clock);
}

static enum gpio_dir stm32_gpio_get_direction(struct gpio_chip *chip,
					      unsigned int gpio_pin)
{
	struct stm32_gpio_bank *bank = gpio_chip_to_bank(chip);
	uint32_t mode = 0;

	assert(gpio_pin < bank->ngpios);

	if (clk_enable(bank->clock))
		panic();

	mode = (io_read32(bank->base + GPIO_MODER_OFFSET) >> (gpio_pin << 1)) &
	       GPIO_MODE_MASK;

	clk_disable(bank->clock);

	switch (mode) {
	case GPIO_MODE_INPUT:
		return GPIO_DIR_IN;
	case GPIO_MODE_OUTPUT:
		return GPIO_DIR_OUT;
	default:
		panic();
	}
}

static void stm32_gpio_set_direction(struct gpio_chip *chip,
				     unsigned int gpio_pin,
				     enum gpio_dir direction)
{
	struct stm32_gpio_bank *bank = gpio_chip_to_bank(chip);
	uint32_t exceptions = 0;
	uint32_t mode = 0;

	assert(gpio_pin < bank->ngpios);

	if (direction == GPIO_DIR_IN)
		mode = GPIO_MODE_INPUT;
	else
		mode = GPIO_MODE_OUTPUT;

	if (clk_enable(bank->clock))
		panic();
	exceptions = cpu_spin_lock_xsave(&gpio_lock);
	io_clrsetbits32(bank->base + GPIO_MODER_OFFSET,
			SHIFT_U32(GPIO_MODE_MASK, gpio_pin << 1),
			SHIFT_U32(mode, gpio_pin << 1));
	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
	clk_disable(bank->clock);
}

static void stm32_gpio_put_gpio(struct gpio_chip *chip __maybe_unused,
				struct gpio *gpio)
{
	assert(is_stm32_gpio_chip(chip));
	free(gpio);
}

static const struct gpio_ops stm32_gpio_ops = {
	.get_direction = stm32_gpio_get_direction,
	.set_direction = stm32_gpio_set_direction,
	.get_value = stm32_gpio_get_level,
	.set_value = stm32_gpio_set_level,
	.put = stm32_gpio_put_gpio,
};

static bool __maybe_unused is_stm32_gpio_chip(struct gpio_chip *chip)
{
	return chip && chip->ops == &stm32_gpio_ops;
}

static struct stm32_gpio_bank *stm32_gpio_get_bank(unsigned int bank_id)
{
	struct stm32_gpio_bank *bank = NULL;

	STAILQ_FOREACH(bank, &bank_list, link)
		if (bank_id == bank->bank_id)
			return bank;

	panic();
}

/* Save to output @cfg the current GPIO (@bank_id/@pin) configuration */
static void __maybe_unused get_gpio_cfg(uint32_t bank_id, uint32_t pin,
					struct gpio_cfg *cfg)
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
	uint32_t exceptions = 0;

	if (clk_enable(bank->clock))
		panic();
	exceptions = cpu_spin_lock_xsave(&gpio_lock);

	/* Load GPIO MODE value, 2bit value shifted by twice the pin number */
	io_clrsetbits32(bank->base + GPIO_MODER_OFFSET,
			SHIFT_U32(GPIO_MODE_MASK, pin << 1),
			SHIFT_U32(cfg->mode, pin << 1));

	/* Load GPIO Output TYPE value, 1bit shifted by pin number value */
	io_clrsetbits32(bank->base + GPIO_OTYPER_OFFSET, BIT(pin),
			SHIFT_U32(cfg->otype, pin));

	/* Load GPIO Output Speed confguration, 2bit value */
	io_clrsetbits32(bank->base + GPIO_OSPEEDR_OFFSET,
			SHIFT_U32(GPIO_OSPEED_MASK, pin << 1),
			SHIFT_U32(cfg->ospeed, pin << 1));

	/* Load GPIO pull configuration, 2bit value */
	io_clrsetbits32(bank->base + GPIO_PUPDR_OFFSET, BIT(pin),
			SHIFT_U32(cfg->pupd, pin << 1));

	/* Load pin mux Alternate Function configuration, 4bit value */
	if (pin < GPIO_ALT_LOWER_LIMIT) {
		io_clrsetbits32(bank->base + GPIO_AFRL_OFFSET,
				SHIFT_U32(GPIO_ALTERNATE_MASK, pin << 2),
				SHIFT_U32(cfg->af, pin << 2));
	} else {
		size_t shift = (pin - GPIO_ALT_LOWER_LIMIT) << 2;

		io_clrsetbits32(bank->base + GPIO_AFRH_OFFSET,
				SHIFT_U32(GPIO_ALTERNATE_MASK, shift),
				SHIFT_U32(cfg->af, shift));
	}

	/* Load GPIO Output direction confuguration, 1bit */
	io_clrsetbits32(bank->base + GPIO_ODR_OFFSET, BIT(pin), cfg->od << pin);

	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
	clk_disable(bank->clock);
}

/* Count pins described in the DT node and get related data if possible */
static int get_pinctrl_from_fdt(const void *fdt, int node,
				struct stm32_pinctrl *pinctrl, size_t count)
{
	const fdt32_t *cuint = NULL;
	const fdt32_t *slewrate = NULL;
	int len = 0;
	uint32_t i = 0;
	uint32_t speed = GPIO_OSPEED_LOW;
	uint32_t pull = GPIO_PUPD_NO_PULL;
	size_t found = 0;

	cuint = fdt_getprop(fdt, node, "pinmux", &len);
	if (!cuint)
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
		uint32_t odata = 0;
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

		if (fdt_getprop(fdt, node, "output-high", NULL) &&
		    mode == GPIO_MODE_INPUT) {
			mode = GPIO_MODE_OUTPUT;
			odata = 1;
		}

		if (fdt_getprop(fdt, node, "output-low", NULL) &&
		    mode == GPIO_MODE_INPUT) {
			mode = GPIO_MODE_OUTPUT;
			odata = 0;
		}

		if (found < count) {
			struct stm32_pinctrl *ref = &pinctrl[found];

			ref->bank = (uint8_t)bank;
			ref->pin = (uint8_t)pin;
			ref->cfg.mode = mode;
			if (opendrain)
				ref->cfg.otype = GPIO_OTYPE_OPEN_DRAIN;
			else
				ref->cfg.otype = GPIO_OTYPE_PUSH_PULL;
			ref->cfg.ospeed = speed;
			ref->cfg.pupd = pull;
			ref->cfg.od = odata;
			ref->cfg.af = alternate;
		}

		found++;
	}

	return (int)found;
}

static TEE_Result stm32_gpio_get_dt(struct dt_pargs *pargs, void *data,
				    struct gpio **out_gpio)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_gpio_bank *bank = data;
	struct gpio *gpio = NULL;
	unsigned int shift_1b = 0;
	unsigned int shift_2b = 0;
	uint32_t exceptions = 0;
	uint32_t otype = 0;
	uint32_t pupd = 0;
	uint32_t mode = 0;

	res = gpio_dt_alloc_pin(pargs, &gpio);
	if (res)
		return res;

	if (gpio->pin >= bank->ngpios) {
		DMSG("Invalid GPIO reference");
		free(gpio);
		return TEE_ERROR_GENERIC;
	}

	shift_1b = gpio->pin;
	shift_2b = SHIFT_U32(gpio->pin, 1);

	if (gpio->dt_flags & GPIO_PULL_UP)
		pupd = GPIO_PUPD_PULL_UP;
	else if (gpio->dt_flags & GPIO_PULL_DOWN)
		pupd = GPIO_PUPD_PULL_DOWN;
	else
		pupd = GPIO_PUPD_NO_PULL;

	if (gpio->dt_flags & GPIO_LINE_OPEN_DRAIN)
		otype = GPIO_OTYPE_OPEN_DRAIN;
	else
		otype = GPIO_OTYPE_PUSH_PULL;

	if (clk_enable(bank->clock))
		panic();
	exceptions = cpu_spin_lock_xsave(&gpio_lock);

	io_clrsetbits32(bank->base + GPIO_MODER_OFFSET,
			SHIFT_U32(GPIO_MODE_MASK, shift_2b),
			SHIFT_U32(mode, shift_2b));

	io_clrsetbits32(bank->base + GPIO_OTYPER_OFFSET,
			SHIFT_U32(GPIO_OTYPE_OPEN_DRAIN, shift_1b),
			SHIFT_U32(otype, shift_1b));

	io_clrsetbits32(bank->base + GPIO_PUPDR_OFFSET,
			SHIFT_U32(GPIO_PUPD_PULL_MASK, shift_2b),
			SHIFT_U32(pupd, shift_2b));

	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
	clk_disable(bank->clock);

	gpio->chip = &bank->gpio_chip;

	*out_gpio = gpio;

	return TEE_SUCCESS;
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
				     const void *compat_data,
				     int range_offset,
				     struct stm32_gpio_bank **out_bank)
{
	const struct bank_compat *compat = compat_data;
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
	bank->bank_id = dt_get_bank_id(fdt, node);
	bank->clock = clk;
	bank->gpio_chip.ops = &stm32_gpio_ops;
	bank->sec_support = compat->secure_control;
	if (bank->sec_support)
		bank->base = io_pa_or_va_secure(&pa_va, blen);
	else
		bank->base = io_pa_or_va_nsec(&pa_va, blen);
	assert(bank->base);

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

	if (compat->gpioz)
		stm32mp_register_gpioz_pin_count(bank->ngpios);

	*out_bank = bank;
	return TEE_SUCCESS;
}

static void set_bank_gpio_non_secure(struct stm32_gpio_bank *bank)
{
	unsigned int pin = 0;

	for (pin = 0; pin < bank->ngpios; pin++)
		stm32_gpio_set_secure_cfg(bank->bank_id, pin, false);
}

/* Parse a pinctrl node to register and configure the GPIO banks it describes */
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

			/* Registering a provider should not defer probe */
			res = gpio_register_provider(fdt, b_node,
						     stm32_gpio_get_dt, bank);
			if (res)
				panic();

			STAILQ_INSERT_TAIL(&bank_list, bank, link);

			DMSG("Registered GPIO bank %c (%d pins) @%#"PRIxVA,
			     bank->bank_id + 'A', bank->ngpios, bank->base);

			assert(bank->ngpios <= GPIO_PIN_MAX + 1);

			if (bank->sec_support) {
				uint32_t seccfgr = 0;
				unsigned int i = 0;
				int lenp = 0;

				cuint = fdt_getprop(fdt, b_node, "st,protreg",
						    &lenp);
				if (!cuint) {
					set_bank_gpio_non_secure(bank);
					continue;
				}

				seccfgr = fdt32_to_cpu(*cuint);
				for (i = 0; i < bank->ngpios; i++)
					stm32_gpio_set_secure_cfg(bank->bank_id,
								  i,
								  seccfgr &
								  TZPROT(i));
			}
		} else {
			if (len != -FDT_ERR_NOTFOUND)
				panic();
		}
	}

	return TEE_SUCCESS;
}

void stm32_gpio_set_secure_cfg(unsigned int bank_id, unsigned int pin,
			       bool secure)
{
	struct stm32_gpio_bank *bank = stm32_gpio_get_bank(bank_id);
	uint32_t exceptions = 0;

	if (clk_enable(bank->clock))
		panic();
	exceptions = cpu_spin_lock_xsave(&gpio_lock);

	if (secure)
		io_setbits32(bank->base + GPIO_SECR_OFFSET, BIT(pin));
	else
		io_clrbits32(bank->base + GPIO_SECR_OFFSET, BIT(pin));

	FMSG("Set secure GPIO: bank %c pin %u", bank->bank_id + 'A', pin);

	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
	clk_disable(bank->clock);
}

#ifdef CFG_DRIVERS_PINCTRL
static TEE_Result stm32_pinctrl_conf_apply(struct pinconf *conf)
{
	struct stm32_pinctrl_array *ref = conf->priv;
	struct stm32_pinctrl *p = ref->pinctrl;
	size_t pin_count = ref->count;
	size_t n = 0;

	for (n = 0; n < pin_count; n++)
		set_gpio_cfg(p[n].bank, p[n].pin, &p[n].cfg);

	return TEE_SUCCESS;
}

static void stm32_pinctrl_conf_free(struct pinconf *conf)
{
	free(conf);
}

static const struct pinctrl_ops stm32_pinctrl_ops = {
	.conf_apply = stm32_pinctrl_conf_apply,
	.conf_free = stm32_pinctrl_conf_free,
};

DECLARE_KEEP_PAGER(stm32_pinctrl_ops);

void stm32_gpio_pinctrl_bank_pin(struct pinctrl_state *pinctrl,
				 unsigned int *bank, unsigned int *pin,
				 unsigned int *count)
{
	size_t conf_index = 0;
	size_t pin_count = 0;
	size_t n = 0;

	assert(count);
	if (!pinctrl)
		goto out;

	for (conf_index = 0; conf_index < pinctrl->conf_count; conf_index++) {
		struct pinconf *pinconf = pinctrl->confs[conf_index];
		struct stm32_pinctrl_array *ref = pinconf->priv;

		/* Consider only the stm32_gpio pins */
		if (pinconf->ops != &stm32_pinctrl_ops)
			continue;

		if (bank || pin) {
			for (n = 0; n < ref->count; n++) {
				if (bank && pin_count < *count)
					bank[pin_count] = ref->pinctrl[n].bank;
				if (pin && pin_count < *count)
					pin[pin_count] = ref->pinctrl[n].pin;
				pin_count++;
			}
		} else {
			pin_count += ref->count;
		}
	}

out:
	*count = pin_count;
}

void stm32_pinctrl_set_secure_cfg(struct pinctrl_state *pinctrl, bool secure)
{
	size_t conf_index = 0;

	if (!pinctrl)
		return;

	for (conf_index = 0; conf_index < pinctrl->conf_count; conf_index++) {
		struct pinconf *pinconf = pinctrl->confs[conf_index];
		struct stm32_pinctrl_array *ref = pinconf->priv;
		struct stm32_pinctrl *pc = NULL;
		size_t n = 0;

		for (n = 0; n < ref->count; n++) {
			if (pinconf->ops != &stm32_pinctrl_ops)
				continue;

			pc = ref->pinctrl + n;
			stm32_gpio_set_secure_cfg(pc->bank, pc->pin, secure);
		}
	}
}

/* Allocate and return a pinctrl configuration from a DT reference */
static TEE_Result stm32_pinctrl_dt_get(struct dt_pargs *pargs,
				       void *data __unused,
				       struct pinconf **out_pinconf)
{
	struct conf {
		struct pinconf pinconf;
		struct stm32_pinctrl_array array_ref;
	} *loc_conf = NULL;
	struct stm32_pinctrl *pinctrl = NULL;
	struct pinconf *pinconf = NULL;
	const void *fdt = NULL;
	size_t pin_count = 0;
	int pinctrl_node = 0;
	int pinmux_node = 0;
	int count = 0;

	pinctrl_node = pargs->phandle_node;
	fdt = pargs->fdt;
	assert(fdt && pinctrl_node);

	fdt_for_each_subnode(pinmux_node, fdt, pinctrl_node) {
		if (fdt_getprop(fdt, pinmux_node, "pinmux", &count))
			pin_count += (size_t)count / sizeof(uint32_t);
		else if (count != -FDT_ERR_NOTFOUND)
			panic();
	}

	loc_conf = calloc(1, sizeof(*loc_conf) + sizeof(*pinctrl) * pin_count);
	if (!loc_conf)
		return TEE_ERROR_OUT_OF_MEMORY;

	pinconf = &loc_conf->pinconf;
	pinconf->ops = &stm32_pinctrl_ops;
	pinconf->priv = &loc_conf->array_ref;

	loc_conf->array_ref.count = pin_count;
	pinctrl = loc_conf->array_ref.pinctrl;

	count = 0;
	fdt_for_each_subnode(pinmux_node, fdt, pinctrl_node) {
		int found = 0;

		found = get_pinctrl_from_fdt(fdt, pinmux_node, pinctrl + count,
					     pin_count - count);
		if (found <= 0 && found > ((int)pin_count - count)) {
			/* We can't recover from an error here so let's panic */
			panic();
		}

		count += found;
	}

	*out_pinconf = pinconf;

	return TEE_SUCCESS;
}
#endif /*CFG_DRIVERS_PINCTRL*/

static TEE_Result stm32_pinctrl_probe(const void *fdt, int node,
				      const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Register GPIO banks described in this pin control node */
	res = dt_stm32_gpio_pinctrl(fdt, node, compat_data);
	if (res)
		return res;

#ifdef CFG_DRIVERS_PINCTRL
	res = pinctrl_register_provider(fdt, node, stm32_pinctrl_dt_get,
					(void *)compat_data);
	if (res)
		return res;
#endif

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_pinctrl_match_table[] = {
	{
		.compatible = "st,stm32mp135-pinctrl",
		.compat_data = &(struct bank_compat){
			.secure_control = true,
		},
	},
	{
		.compatible = "st,stm32mp157-pinctrl",
		.compat_data = &(struct bank_compat){
			.secure_control = false,
		},
	},
	{
		.compatible = "st,stm32mp157-z-pinctrl",
		.compat_data = &(struct bank_compat){
			.gpioz = true,
			.secure_control = true,
		},
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_pinctrl_dt_driver) = {
	.name = "stm32_gpio-pinctrl",
	.type = DT_DRIVER_PINCTRL,
	.match_table = stm32_pinctrl_match_table,
	.probe = stm32_pinctrl_probe,
};
