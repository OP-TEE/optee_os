/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, 2020, Linaro Limited
 */
#ifndef KERNEL_EARLY_TA_H
#define KERNEL_EARLY_TA_H

#include <scattered_array.h>
#include <stdint.h>
#include <tee_api_types.h>

struct early_ta {
	uint32_t flags;
	TEE_UUID uuid;
	uint32_t size;
	uint32_t uncompressed_size; /* 0: not compressed */
	const uint8_t *ta; /* @size bytes */
};

#define for_each_early_ta(_ta) \
	SCATTERED_ARRAY_FOREACH(_ta, early_tas, struct early_ta)

#endif /* KERNEL_EARLY_TA_H */

