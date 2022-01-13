// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/atmel_rstc.h>
#include <io.h>
#include <kernel/dt.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define AT91_RSTC_CR		0x0
#define AT91_RSTC_CR_KEY	SHIFT_U32(0xA5, 24)
#define AT91_RSTC_CR_PROCRST	BIT32(0)
#define AT91_RSTC_CR_PERRST	BIT32(2)

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

static TEE_Result atmel_rstc_probe(const void *fdt, int node,
				   const void *compat_data __unused)

{
	size_t size = 0;

	if (dt_map_dev(fdt, node, &rstc_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_rstc_match_table[] = {
	{ .compatible = "atmel,sama5d3-rstc" },
	{ }
};

DEFINE_DT_DRIVER(atmel_rstc_dt_driver) = {
	.name = "atmel_rstc",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_rstc_match_table,
	.probe = atmel_rstc_probe,
};
