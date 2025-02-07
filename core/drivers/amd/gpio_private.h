/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2002-2021 Xilinx, Inc.  All rights reserved.
 * Copyright (c) 2022 Foundries.io Ltd. (jorge@foundries.io)
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __GPIO_PRIVATE_H__
#define __GPIO_PRIVATE_H__

#include <drivers/gpio.h>
#include <kernel/dt.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <util.h>

#define GPIO_MAX_BANK		6

#define PS_BANK_MAX		4

#define GPIO_NUM_MAX		16

#define GPIO_UPPER_MASK		GENMASK_32(31, 16)

#define DATA_LSW_OFFSET(__bank)	(0x000 + 0x8 * (__bank))
#define DATA_MSW_OFFSET(__bank)	(0x004 + 0x8 * (__bank))
#define DATA_RO_OFFSET(__bank)	(0x060 + 0x4 * (__bank))
#define DIRM_OFFSET(__bank)	(0x204 + 0x40 * (__bank))
#define OUTEN_OFFSET(__bank)	(0x208 + 0x40 * (__bank))
#define INTMASK_OFFSET(__bank)	(0x20c + 0x40 * (__bank))
#define INTEN_OFFSET(__bank)	(0x210 + 0x40 * (__bank))
#define INTDIS_OFFSET(__bank)	(0x214 + 0x40 * (__bank))

struct amd_gbank_data {
	const char *label;
	uint16_t ngpio;
	uint32_t max_bank;
	uint32_t bank_min[GPIO_MAX_BANK];
	uint32_t bank_max[GPIO_MAX_BANK];
};

struct amd_gpio_info {
	struct amd_gbank_data *bdata;
	struct gpio_chip chip;
	vaddr_t vbase;
};

void amd_gpio_get_bank_and_pin(struct amd_gbank_data *bdata, uint32_t gpio,
			       uint32_t *bank, uint32_t *pin);
TEE_Result amd_gpio_get_dt(struct dt_pargs *pargs, void *data,
			   struct gpio **out_gpio);

#endif /* __GPIO_PRIVATE_H__  */
