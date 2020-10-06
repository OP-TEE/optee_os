/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */
#ifndef KERNEL_EMBEDDED_TS_H
#define KERNEL_EMBEDDED_TS_H

#include <compiler.h>
#include <kernel/linker.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

struct embedded_ts {
	uint32_t flags;
	TEE_UUID uuid;
	uint32_t size;
	uint32_t uncompressed_size; /* 0: not compressed */
	const uint8_t *ts; /* @size bytes */
};

#endif /* KERNEL_EMBEDDED_TS_H */

