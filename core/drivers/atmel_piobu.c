// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 *
 * Driver for AT91 PIOBU
 */

#include <assert.h>
#include <drivers/atmel_rtc.h>
#include <dt-bindings/gpio/atmel,piobu.h>
#include <gpio.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>

#define SECUMOD_MAX_PINS		8
#define SECUMOD_PIN_MASK		(BIT(SECUMOD_MAX_PINS) - 1)
#define SECUMOD_PIN_SHIFT		16
#define SECUMOD_PIN_VAL(pin)		BIT(SECUMOD_PIN_SHIFT + (pin))

#define DT_GPIO_CELLS			2

#define SECUMOD_CR			0x0
#define SECUMOD_CR_KEY_SHIFT		16
#define SECUMOD_CR_KEY			SHIFT_U32(0x89CA, SECUMOD_CR_KEY_SHIFT)
#define SECUMOD_CR_BACKUP		BIT(0)
#define SECUMOD_CR_NORMAL		BIT(1)

#define SECUMOD_SR			0x8
#define SECUMOD_SR_JTAG			BIT(3)
#define SECUMOD_SR_TST_PIN			BIT(2)

#define SECUMOD_SCR			0x10

#define SECUMOD_PIOBU(x)		(0x18 + (x) * 0x4)
#define SECUMOD_PIOBU_AFV_MASK		GENMASK_32(3, 0)
#define SECUMOD_PIOBU_RFV_SHIFT		4
#define SECUMOD_PIOBU_OUTPUT		BIT(8)
#define SECUMOD_PIOBU_SOD		BIT(9)
#define SECUMOD_PIOBU_PDS		BIT(10)
#define SECUMOD_PIOBU_PULLUP_SHIFT	12
#define SECUMOD_PIOBU_SWITCH_SHIFT	15

#define SECUMOD_JTAGCR			0x68
#define SECUMOD_JTAGCR_FNTRST		0x1

#define SECUMOD_BMPR			0x7C
#define SECUMOD_NMPR			0x80
#define SECUMOD_NIEPR			0x84
#define SECUMOD_NIDPR			0x88
#define SECUMOD_NIMPR			0x8C
#define SECUMOD_WKPR			0x90

static vaddr_t secumod_base;
static uint32_t gpio_protected;
static struct gpio_chip secumod_chip;

/*
 * Get value from GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin from which value needs to be read
 * Return target GPIO pin level.
 */
static enum gpio_level gpio_get_value(struct gpio_chip *chip __unused,
				      unsigned int gpio_pin)
{
	vaddr_t piobu_addr = 0;
	uint32_t piobu = 0;

	assert(gpio_pin < SECUMOD_MAX_PINS &&
	       !(gpio_protected & BIT32(gpio_pin)));

	piobu_addr = secumod_base + SECUMOD_PIOBU(gpio_pin);
	piobu = io_read32(piobu_addr);

	if (piobu & SECUMOD_PIOBU_PDS)
		return GPIO_LEVEL_HIGH;
	else
		return GPIO_LEVEL_LOW;
}

/*
 * Set value for GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin to which value needs to be written
 * value:       Level state for the target pin
 */
static void gpio_set_value(struct gpio_chip *chip __unused,
			   unsigned int gpio_pin, enum gpio_level value)
{
	vaddr_t piobu_addr = 0;

	assert(gpio_pin < SECUMOD_MAX_PINS &&
	       !(gpio_protected & BIT32(gpio_pin)));

	piobu_addr = secumod_base + SECUMOD_PIOBU(gpio_pin);

	if (value == GPIO_LEVEL_HIGH)
		io_setbits32(piobu_addr, SECUMOD_PIOBU_SOD);
	else
		io_clrbits32(piobu_addr, SECUMOD_PIOBU_SOD);
}

/*
 * Get direction from GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin from which direction needs to be read
 */
static enum gpio_dir gpio_get_direction(struct gpio_chip *chip __unused,
					unsigned int gpio_pin)
{
	vaddr_t piobu_addr = 0;
	uint32_t piobu = 0;

	assert(gpio_pin < SECUMOD_MAX_PINS &&
	       !(gpio_protected & BIT32(gpio_pin)));

	piobu_addr = secumod_base + SECUMOD_PIOBU(gpio_pin);
	piobu = io_read32(piobu_addr);

	if (piobu & SECUMOD_PIOBU_OUTPUT)
		return GPIO_DIR_OUT;
	else
		return GPIO_DIR_IN;
}

/*
 * Set direction for GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin on which direction needs to be set
 * direction:   direction which needs to be set on pin
 */
static void gpio_set_direction(struct gpio_chip *chip __unused,
			       unsigned int gpio_pin, enum gpio_dir direction)
{
	vaddr_t piobu_addr = 0;

	assert(gpio_pin < SECUMOD_MAX_PINS &&
	       !(gpio_protected & BIT32(gpio_pin)));

	piobu_addr = secumod_base + SECUMOD_PIOBU(gpio_pin);

	if (direction == GPIO_DIR_OUT)
		io_setbits32(piobu_addr, SECUMOD_PIOBU_OUTPUT);
	else
		io_clrbits32(piobu_addr, SECUMOD_PIOBU_OUTPUT);
}

/*
 * Get interrupt from GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin from which interrupt value needs to be read
 */
static enum gpio_interrupt gpio_get_interrupt(struct gpio_chip *chip __unused,
					      unsigned int gpio_pin)
{
	vaddr_t nimpr_addr = secumod_base + SECUMOD_NIMPR;
	uint32_t data = 0;

	assert(gpio_pin < SECUMOD_MAX_PINS &&
	       !(gpio_protected & BIT32(gpio_pin)));

	data = io_read32(nimpr_addr);

	if (data & SECUMOD_PIN_VAL(gpio_pin))
		return GPIO_INTERRUPT_ENABLE;
	else
		return GPIO_INTERRUPT_DISABLE;
}

/*
 * Set interrupt event for GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin on which interrupt value needs to be set
 * interrupt:   interrupt value which needs to be set on pin
 */
static void gpio_set_interrupt(struct gpio_chip *chip __unused,
			       unsigned int gpio_pin,
			       enum gpio_interrupt interrupt)
{
	vaddr_t niepr_addr = secumod_base + SECUMOD_NIEPR;

	assert(gpio_pin < SECUMOD_MAX_PINS &&
	       !(gpio_protected & BIT32(gpio_pin)));

	if (interrupt == GPIO_INTERRUPT_ENABLE)
		io_setbits32(niepr_addr, SECUMOD_PIN_VAL(gpio_pin));
	else
		io_clrbits32(niepr_addr, SECUMOD_PIN_VAL(gpio_pin));
}

static const struct gpio_ops atmel_piobu_ops = {
	.get_direction = gpio_get_direction,
	.set_direction = gpio_set_direction,
	.get_value = gpio_get_value,
	.set_value = gpio_set_value,
	.get_interrupt = gpio_get_interrupt,
	.set_interrupt = gpio_set_interrupt,
};

static enum itr_return secumod_it_handler(struct itr_handler *handler __unused)
{
	int i = 0;
	struct optee_rtc_time tm = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sr = io_read32(secumod_base + SECUMOD_SR);

	for (i = 0; i < SECUMOD_MAX_PINS; i++) {
		if (sr & SECUMOD_PIN_VAL(i))
			EMSG("Detected tampering on pin %d", i);
	}

	if (sr & SECUMOD_SR_JTAG)
		EMSG("JTAG tampering attempt");

	if (sr & SECUMOD_SR_TST_PIN)
		EMSG("Test pin tampering attempt");

	res = atmel_rtc_get_tamper_timestamp(&tm);
	if (!res) {
		EMSG("Date of tampering: %02"PRIu32"/%02"PRIu32"/%02"PRIu32"",
		     tm.tm_mday, tm.tm_mon, tm.tm_year);
		EMSG("Time of tampering: %02"PRIu32":%02"PRIu32":%02"PRIu32"",
		     tm.tm_hour, tm.tm_min, tm.tm_sec);
	}

	io_write32(secumod_base + SECUMOD_SCR,
		   SECUMOD_PIN_MASK << SECUMOD_PIN_SHIFT);

	panic("Tampering detected, system halted");

	return ITRR_HANDLED;
}

static struct itr_handler secumod_itr_handler = {
	.it = AT91C_ID_SECUMOD,
	.handler = secumod_it_handler,
};

static void secumod_interrupt_init(void)
{
	itr_add_type_prio(&secumod_itr_handler, IRQ_TYPE_LEVEL_HIGH, 7);
	itr_enable(secumod_itr_handler.it);
}

static void secumod_cfg_input_pio(uint8_t gpio_pin, uint32_t config)
{
	vaddr_t piobu_addr = 0;
	uint8_t afv = 0;
	uint8_t rfv = 0;
	uint8_t pull_mode = PIOBU_PIN_PULL_NONE;
	uint8_t def_level = PIOBU_PIN_DEF_LEVEL_LOW;

	assert(gpio_pin < SECUMOD_MAX_PINS);

	piobu_addr = secumod_base + SECUMOD_PIOBU(gpio_pin);

	/* Set GPIO as input */
	io_clrbits32(piobu_addr, SECUMOD_PIOBU_OUTPUT);

	afv = PIOBU_PIN_AFV(config);
	rfv = PIOBU_PIN_RFV(config);
	pull_mode = PIOBU_PIN_PULL_MODE(config);
	def_level = PIOBU_PIN_DEF_LEVEL(config);

	io_write32(piobu_addr, afv | rfv << SECUMOD_PIOBU_RFV_SHIFT |
		   pull_mode << SECUMOD_PIOBU_PULLUP_SHIFT |
		   def_level << SECUMOD_PIOBU_SWITCH_SHIFT);

	/* Enable Tampering Interrupt */
	gpio_set_interrupt(&secumod_chip, gpio_pin, GPIO_INTERRUPT_ENABLE);

	/* Enable Intrusion Detection */
	io_setbits32(secumod_base + SECUMOD_NMPR, SECUMOD_PIN_VAL(gpio_pin));

	/* Enable Wakeup */
	if (PIOBU_PIN_WAKEUP(config))
		io_setbits32(secumod_base + SECUMOD_WKPR,
			     SECUMOD_PIN_VAL(gpio_pin));

	gpio_protected |= BIT32(gpio_pin);
}

static void secumod_hw_init(const void *fdt, int node)
{
	int i = 0;
	int len = 0;
	uint8_t gpio_pin = 0;
	uint32_t config = 0;
	const uint32_t *prop = NULL;

	/* Disable JTAG Reset and Debug */
	io_write32(secumod_base + SECUMOD_JTAGCR, SECUMOD_JTAGCR_FNTRST);

	/* Switch IOs to normal mode */
	io_write32(secumod_base + SECUMOD_CR, SECUMOD_CR_KEY |
		   SECUMOD_CR_NORMAL);

	/* Clear all detection intrusion in normal mode */
	io_write32(secumod_base + SECUMOD_NMPR, 0);

	/* Clear Alarms */
	io_write32(secumod_base + SECUMOD_SCR,
		   SECUMOD_PIN_MASK << SECUMOD_PIN_SHIFT);

	/* Configure each IOs */
	prop = fdt_getprop(fdt, node, "gpios", &len);
	if (!prop)
		return;

	len /= sizeof(uint32_t);
	for (i = 0; i < len; i += DT_GPIO_CELLS) {
		gpio_pin = fdt32_to_cpu(prop[i]);
		config = fdt32_to_cpu(prop[i + 1]);

		secumod_cfg_input_pio(gpio_pin, config);
	}
}

#ifdef CFG_PM_ARM32
static TEE_Result piobu_pm(enum pm_op op, uint32_t pm_hint __unused,
			   const struct pm_callback_handle *hdl __unused)
{
	switch (op) {
	case PM_OP_RESUME:
		io_write32(secumod_base + SECUMOD_CR, SECUMOD_CR_KEY |
			   SECUMOD_CR_NORMAL);
		break;
	case PM_OP_SUSPEND:
		/* Enter backup mode before suspending */
		io_write32(secumod_base + SECUMOD_CR, SECUMOD_CR_KEY |
			   SECUMOD_CR_BACKUP);
		break;
	default:
		panic("Invalid PM operation");
	}

	return TEE_SUCCESS;
}

static void piobu_register_pm(void)
{
	register_pm_driver_cb(piobu_pm, NULL, "piobu");
}
#else
static void piobu_register_pm(void) {}
#endif

static TEE_Result atmel_secumod_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	size_t size = 0;

	if (secumod_base)
		return TEE_ERROR_GENERIC;

	if (dt_map_dev(fdt, node, &secumod_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	secumod_hw_init(fdt, node);
	secumod_interrupt_init();

	secumod_chip.ops = &atmel_piobu_ops;

	piobu_register_pm();

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_secumod_match_table[] = {
	{ .compatible = "atmel,sama5d2-secumod" },
	{ }
};

DEFINE_DT_DRIVER(atmel_secumod_dt_driver) = {
	.name = "atmel_secumod",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_secumod_match_table,
	.probe = atmel_secumod_probe,
};
