// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, Linaro Limited
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#include <drivers/rstctrl.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>

#include "stm32_rstctrl.h"

static struct stm32_reset_data *stm32_reset_pdata;

static SLIST_HEAD(, stm32_rstline) stm32_rst_list =
	SLIST_HEAD_INITIALIZER(stm32_rst_list);

static struct stm32_rstline *find_rstctrl_device(unsigned int control_id)
{
	struct stm32_rstline *stm32_rstline = NULL;

	SLIST_FOREACH(stm32_rstline, &stm32_rst_list, link)
		if (stm32_rstline->id == control_id)
			break;

	return stm32_rstline;
}

static struct
stm32_rstline *find_or_allocate_rstline(unsigned int binding_id,
					const struct stm32_reset_data *pdata)
{
	struct stm32_rstline *stm32_rstline = find_rstctrl_device(binding_id);

	if (stm32_rstline)
		return stm32_rstline;

	stm32_rstline = calloc(1, sizeof(*stm32_rstline));
	if (stm32_rstline) {
		assert(pdata->get_rstctrl_ops);

		stm32_rstline->id = binding_id;
		stm32_rstline->data = pdata;
		stm32_rstline->rstctrl.ops = pdata->get_rstctrl_ops(binding_id);

		SLIST_INSERT_HEAD(&stm32_rst_list, stm32_rstline, link);
	}

	return stm32_rstline;
}

struct stm32_rstline *to_stm32_rstline(struct rstctrl *rstctrl)
{
	assert(rstctrl);

	return container_of(rstctrl, struct stm32_rstline, rstctrl);
}

struct rstctrl *stm32mp_rcc_reset_id_to_rstctrl(unsigned int binding_id)
{
	struct stm32_rstline *rstline = NULL;

	rstline = find_or_allocate_rstline(binding_id, stm32_reset_pdata);

	assert(rstline);
	return &rstline->rstctrl;
}

static TEE_Result stm32_rstctrl_get_dev(struct dt_pargs *arg,
					void *priv_data,
					struct rstctrl **out_device)
{
	struct stm32_rstline *stm32_rstline = NULL;
	uintptr_t control_id = 0;

	if (arg->args_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	control_id = arg->args[0];

	stm32_rstline = find_or_allocate_rstline(control_id, priv_data);
	if (!stm32_rstline)
		return TEE_ERROR_OUT_OF_MEMORY;

	*out_device = &stm32_rstline->rstctrl;

	return TEE_SUCCESS;
}

TEE_Result stm32_rstctrl_provider_probe(const void *fdt, int offs,
					const void *compat_data)
{
	struct dt_node_info info = { };

	stm32_reset_pdata = (struct stm32_reset_data *)compat_data;

	fdt_fill_device_info(fdt, &info, offs);

	assert(info.reg == RCC_BASE &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	return rstctrl_register_provider(fdt, offs, stm32_rstctrl_get_dev,
					 stm32_reset_pdata);
}
