// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 */

#include <assert.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <util.h>

#define STAT		0x14
#define DATA		0x1C
#define UART_SIZE	0x20
#define STAT_TDRE	BIT(23)
#define STAT_RDRF	BIT(21)
#define STAT_OR		BIT(19)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct imx_uart_data *pd =
		container_of(chip, struct imx_uart_data, chip);

	return io_pa_or_va(&pd->base, UART_SIZE);
}

static int imx_lpuart_getchar(struct serial_chip *chip)
{
	int ch = 0;
	vaddr_t base = chip_to_base(chip);

	while (io_read32(base + STAT) & STAT_RDRF)
		;

	ch = io_read32(base + DATA) & 0x3ff;

	if (io_read32(base + STAT) & STAT_OR)
		io_write32(base + STAT, STAT_OR);

	return ch;
}

static void imx_lpuart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + STAT) & STAT_TDRE))
		;

	io_write32(base + DATA, ch);
}

static const struct serial_ops imx_lpuart_ops = {
	.getchar = imx_lpuart_getchar,
	.putc = imx_lpuart_putc,
};
DECLARE_KEEP_PAGER(imx_lpuart_ops);

void imx_uart_init(struct imx_uart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &imx_lpuart_ops;

	/*
	 * Do nothing, debug uart(sc lpuart) shared with normal world,
	 * everything for uart initialization is done in bootloader.
	 */
}

#ifdef CFG_DT
static struct serial_chip *imx_lpuart_dev_alloc(void)
{
	struct imx_uart_data *pd = calloc(1, sizeof(*pd));

	if (!pd)
		return NULL;

	return &pd->chip;
}

static int imx_lpuart_dev_init(struct serial_chip *chip, const void *fdt,
			       int offs, const char *parms)
{
	struct imx_uart_data *pd =
		container_of(chip, struct imx_uart_data, chip);
	vaddr_t vbase = 0;
	paddr_t pbase = 0;
	size_t size = 0;

	if (parms && parms[0])
		IMSG("imx_lpuart: device parameters ignored (%s)", parms);

	if (dt_map_dev(fdt, offs, &vbase, &size, DT_MAP_AUTO) < 0)
		return -1;

	pbase = virt_to_phys((void *)vbase);
	imx_uart_init(pd, pbase);

	return 0;
}

static void imx_lpuart_dev_free(struct serial_chip *chip)
{
	struct imx_uart_data *pd =
		container_of(chip, struct imx_uart_data, chip);

	free(pd);
}

static const struct serial_driver imx_lpuart_driver = {
	.dev_alloc = imx_lpuart_dev_alloc,
	.dev_init = imx_lpuart_dev_init,
	.dev_free = imx_lpuart_dev_free,
};

static const struct dt_device_match imx_match_table[] = {
	{ .compatible = "fsl,imx7ulp-lpuart" },
	{ .compatible = "fsl,imx8qm-lpuart" },
	{ 0 }
};

DEFINE_DT_DRIVER(imx_dt_driver) = {
	.name = "imx_lpuart",
	.type = DT_DRIVER_UART,
	.match_table = imx_match_table,
	.driver = &imx_lpuart_driver,
};

#endif /* CFG_DT */
