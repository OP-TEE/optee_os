// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/atmel_rstc.h>
#include <drivers/rstctrl.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <malloc.h>
#include <matrix.h>
#include <platform_config.h>
#include <stdbool.h>
#include <sys/queue.h>
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

struct sam_reset_data {
	bool rstc_always_secure;
	const struct rstctrl_ops *ops;
};

struct sam_rstline {
	unsigned int reset_id;
	struct rstctrl rstctrl;
	SLIST_ENTRY(sam_rstline) link;
};

static SLIST_HEAD(, sam_rstline) sam_rst_list =
	SLIST_HEAD_INITIALIZER(sam_rst_list);

static struct sam_rstline *to_sam_rstline(struct rstctrl *ptr)
{
	assert(ptr);

	return container_of(ptr, struct sam_rstline, rstctrl);
}

static struct sam_rstline *find_rstline(unsigned int reset_id)
{
	struct sam_rstline *sam_rstline = NULL;

	SLIST_FOREACH(sam_rstline, &sam_rst_list, link)
		if (sam_rstline->reset_id == reset_id)
			break;

	return sam_rstline;
}

static struct
sam_rstline *find_or_allocate_rstline(unsigned int reset_id,
				      const struct sam_reset_data *pdata)
{
	struct sam_rstline *sam_rstline = find_rstline(reset_id);

	if (sam_rstline)
		return sam_rstline;

	sam_rstline = calloc(1, sizeof(*sam_rstline));
	if (sam_rstline) {
		sam_rstline->reset_id = reset_id;
		sam_rstline->rstctrl.ops = pdata->ops;

		SLIST_INSERT_HEAD(&sam_rst_list, sam_rstline, link);
	}

	return sam_rstline;
}

static TEE_Result sam_rstctrl_dt_get(struct dt_pargs *args, void *data,
				     struct rstctrl **out_rstctrl)
{
	struct sam_rstline *sam_rstline = NULL;

	if (args->args_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	sam_rstline = find_or_allocate_rstline(args->args[0], data);
	if (!sam_rstline)
		return TEE_ERROR_OUT_OF_MEMORY;

	*out_rstctrl = &sam_rstline->rstctrl;

	return TEE_SUCCESS;
}

static TEE_Result reset_assert(struct rstctrl *rstctrl,
			       unsigned int to_us __unused)
{
	unsigned int id = to_sam_rstline(rstctrl)->reset_id;

	io_setbits32(rstc_base + RESET_OFFSET(id), BIT(RESET_BIT_POS(id)));
	dsb();

	return TEE_SUCCESS;
}

static TEE_Result reset_deassert(struct rstctrl *rstctrl,
				 unsigned int to_us __unused)
{
	unsigned int id = to_sam_rstline(rstctrl)->reset_id;

	io_clrbits32(rstc_base + RESET_OFFSET(id), BIT(RESET_BIT_POS(id)));
	dsb();

	return TEE_SUCCESS;
}

static const struct rstctrl_ops sama7_rstc_ops = {
	.assert_level = reset_assert,
	.deassert_level = reset_deassert,
};
DECLARE_KEEP_PAGER(sama7_rstc_ops);

static const struct sam_reset_data sama7_reset_data = {
	.rstc_always_secure = true,
	.ops = &sama7_rstc_ops
};
DECLARE_KEEP_PAGER(sama7_reset_data);

struct rstctrl *sam_get_rstctrl(unsigned int reset_id)
{
	struct sam_rstline *rstline = NULL;

	rstline = find_or_allocate_rstline(reset_id, &sama7_reset_data);
	assert(rstline);

	return &rstline->rstctrl;
}

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

static TEE_Result atmel_rstc_probe(const void *fdt, int node,
				   const void *compat_data)

{
	struct sam_reset_data *pdata = (struct sam_reset_data *)compat_data;
	size_t size = 0;

	if (fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_BAD_PARAMETERS;

	if (pdata && pdata->rstc_always_secure)
		matrix_configure_periph_secure(AT91C_ID_SYS);

	if (dt_map_dev(fdt, node, &rstc_base, &size, DT_MAP_AUTO) < 0)
		return TEE_ERROR_GENERIC;

	if (pdata)
		return rstctrl_register_provider(fdt, node, sam_rstctrl_dt_get,
						 pdata);

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_rstc_match_table[] = {
	{ .compatible = "atmel,sama5d3-rstc" },
	{
		.compatible = "microchip,sama7g5-rstc",
		.compat_data = &sama7_reset_data,
	},
	{ }
};

DEFINE_DT_DRIVER(atmel_rstc_dt_driver) = {
	.name = "atmel_rstc",
	.type = DT_DRIVER_RSTCTRL,
	.match_table = atmel_rstc_match_table,
	.probe = atmel_rstc_probe,
};
