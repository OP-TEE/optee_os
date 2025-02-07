// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2002-2021 Xilinx, Inc.  All rights reserved.
 * Copyright (c) 2022 Foundries.io Ltd. (jorge@foundries.io)
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <trace.h>

#include "gpio_private.h"

void amd_gpio_get_bank_and_pin(struct amd_gbank_data *bdata, uint32_t gpio,
			       uint32_t *bank, uint32_t *pin)
{
	uint32_t i = 0;

	assert(gpio < bdata->ngpio);

	for (i = 0; i < bdata->max_bank; i++) {
		if (gpio >= bdata->bank_min[i] &&
		    gpio <= bdata->bank_max[i]) {
			*bank = i;
			*pin = gpio - bdata->bank_min[i];
			return;
		}
	}

	/* Ideally, should never reach over here */
	EMSG("Invalid GPIO pin number: %"PRIu32, gpio);
	panic();
}

TEE_Result amd_gpio_get_dt(struct dt_pargs *pargs, void *data,
			   struct gpio **out_gpio)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct amd_gpio_info *amd = (struct amd_gpio_info *)data;
	struct gpio *gpio = NULL;

	res = gpio_dt_alloc_pin(pargs, &gpio);
	if (res)
		return res;

	if (gpio->pin >= amd->bdata->ngpio) {
		DMSG("GPIO is outside of GPIO Range");
		free(gpio);
		return TEE_ERROR_GENERIC;
	}

	gpio->chip = &amd->chip;
	*out_gpio = gpio;

	return TEE_SUCCESS;
}
