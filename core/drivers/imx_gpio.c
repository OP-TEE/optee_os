// SPDX-License-Identifier: BSD-2-Clause
/*
 * i.MX GPIO controller ("fsl,imx35-gpio": i.MX6/7/8M), GPIO provider for
 * the secure DT. A bank may be shared with the normal world, so only the
 * requested pin is changed, with read-modify-write cycles.
 */
#include <drivers/gpio.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <malloc.h>
#include <util.h>

#define GPIO_DR		0x00	/* data */
#define GPIO_GDIR	0x04	/* direction, 1 = output */
#define GPIO_PSR	0x08	/* pad status */

#define IMX_GPIO_PINS	32

struct imx_gpio {
	struct gpio_chip chip;
	vaddr_t base;
	unsigned int lock;
};

static struct imx_gpio *to_imx_gpio(struct gpio_chip *chip)
{
	return container_of(chip, struct imx_gpio, chip);
}

static void imx_gpio_update(struct imx_gpio *g, uint32_t reg,
			    unsigned int pin, bool set)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g->lock);

	if (set)
		io_setbits32(g->base + reg, BIT32(pin));
	else
		io_clrbits32(g->base + reg, BIT32(pin));

	cpu_spin_unlock_xrestore(&g->lock, exceptions);
}

static enum gpio_dir imx_gpio_get_direction(struct gpio_chip *chip,
					    unsigned int pin)
{
	if (io_read32(to_imx_gpio(chip)->base + GPIO_GDIR) & BIT32(pin))
		return GPIO_DIR_OUT;

	return GPIO_DIR_IN;
}

static void imx_gpio_set_direction(struct gpio_chip *chip, unsigned int pin,
				   enum gpio_dir dir)
{
	imx_gpio_update(to_imx_gpio(chip), GPIO_GDIR, pin, dir == GPIO_DIR_OUT);
}

static enum gpio_level imx_gpio_get_value(struct gpio_chip *chip,
					  unsigned int pin)
{
	if (io_read32(to_imx_gpio(chip)->base + GPIO_PSR) & BIT32(pin))
		return GPIO_LEVEL_HIGH;

	return GPIO_LEVEL_LOW;
}

static void imx_gpio_set_value(struct gpio_chip *chip, unsigned int pin,
			       enum gpio_level level)
{
	imx_gpio_update(to_imx_gpio(chip), GPIO_DR, pin,
			level == GPIO_LEVEL_HIGH);
}

static void imx_gpio_put(struct gpio_chip *chip __unused, struct gpio *gpio)
{
	free(gpio);
}

static const struct gpio_ops imx_gpio_ops = {
	.get_direction = imx_gpio_get_direction,
	.set_direction = imx_gpio_set_direction,
	.get_value = imx_gpio_get_value,
	.set_value = imx_gpio_set_value,
	.put = imx_gpio_put,
};

static TEE_Result imx_gpio_dt_get(struct dt_pargs *pargs, void *data,
				  struct gpio **out_gpio)
{
	struct imx_gpio *g = data;
	struct gpio *gpio = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = gpio_dt_alloc_pin(pargs, &gpio);
	if (res)
		return res;

	if (gpio->pin >= IMX_GPIO_PINS) {
		free(gpio);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	gpio->chip = &g->chip;
	*out_gpio = gpio;

	return TEE_SUCCESS;
}

static TEE_Result imx_gpio_probe(const void *fdt, int node,
				 const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_gpio *g = NULL;
	size_t size = 0;

	if (!(fdt_get_status(fdt, node) & DT_STATUS_OK_SEC))
		return TEE_SUCCESS;

	g = calloc(1, sizeof(*g));
	if (!g)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (dt_map_dev(fdt, node, &g->base, &size, DT_MAP_AUTO) < 0) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}
	g->chip.ops = &imx_gpio_ops;
	g->lock = SPINLOCK_UNLOCK;

	res = gpio_register_provider(fdt, node, imx_gpio_dt_get, g);
	if (res)
		goto err;

	return TEE_SUCCESS;
err:
	free(g);

	return res;
}

GPIO_DT_DECLARE(imx_gpio, "fsl,imx35-gpio", imx_gpio_probe);
