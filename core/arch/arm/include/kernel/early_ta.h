/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */
#ifndef KERNEL_EARLY_TA_H
#define KERNEL_EARLY_TA_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api_types.h>

struct early_ta {
	TEE_UUID uuid;
	uint32_t size;
	uint32_t uncompressed_size; /* 0: not compressed */
	const uint8_t ta[]; /* @size bytes */
};

#define __early_ta __section(".rodata.early_ta" __SECTION_FLAGS_RODATA)

#endif /* KERNEL_EARLY_TA_H */

