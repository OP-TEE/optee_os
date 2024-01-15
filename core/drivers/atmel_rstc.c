// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/atmel_rstc.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <matrix.h>
#include <platform_config.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define AT91_RSTC_CR		0x0
#define AT91_RSTC_CR_KEY	SHIFT_U32(0xA5, 24)
#define AT91_RSTC_CR_PROCRST	BIT32(0)
#define AT91_RSTC_CR_PERRST	BIT32(2)

#define AT91_RSTC_GRSTR		0xE4
#define AT91_RSTC_GRSTR_USB(x)	SHIFT_U32(1, 4 + (x))

static vaddr_t rstc_base;

bool atmel_rstc_available(void)
{
	return rstc_base != 0;
}

void __noreturn atmel_rstc_reset(void)
{
	uint32_t val = AT91_RSTC_CR_KEY | AT91_RSTC_CR_PROCRST |
		       AT91_RSTC_CR_PERRST;

	io_write32(rstc_base + AT91_RSTC_CR, val);

	/*
	 * After the previous write, the CPU will reset so we will never hit
	 * this loop.
	 */
	while (true)
		;
}

void sam_rstc_usb_por(unsigned char id, bool enable)
{
	if (!atmel_rstc_available())
		panic();

	if (enable)
		io_setbits32(rstc_base + AT91_RSTC_GRSTR,
			     AT91_RSTC_GRSTR_USB(id));
	else
		io_clrbits32(rstc_base + AT91_RSTC_GRSTR,
			     AT91_RSTC_GRSTR_USB(id));
}

/* Non-null reference for compat data */
static const uint8_t rstc_always_secure;

static TEE_Result atmel_rstc_probe(const void *fdt, int node,
				   const void *compat_data)

{
	size_t size = 0;

	if (fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_BAD_PARAMETERS;

	if (compat_data != &rstc_always_secure)
		matrix_configure_periph_secure(AT91C_ID_SYS);

	if (dt_map_dev(fdt, node, &rstc_base, &size, DT_MAP_AUTO) < 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_rstc_match_table[] = {
	{ .compatible = "atmel,sama5d3-rstc" },
	{
		.compatible = "microchip,sama7g5-rstc",
		.compat_data = &rstc_always_secure,
	},
	{ }
};

DEFINE_DT_DRIVER(atmel_rstc_dt_driver) = {
	.name = "atmel_rstc",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_rstc_match_table,
	.probe = atmel_rstc_probe,
};
