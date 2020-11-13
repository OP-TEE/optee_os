/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */
#ifndef KERNEL_EARLY_TA_H
#define KERNEL_EARLY_TA_H

#include <compiler.h>
#include <kernel/linker.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

struct early_ta {
	uint32_t flags;
	TEE_UUID uuid;
	uint32_t size;
	uint32_t uncompressed_size; /* 0: not compressed */
	const uint8_t ta[]; /* @size bytes */
};

#define __early_ta __section(".rodata.early_ta" __SECTION_FLAGS_RODATA)

#define for_each_early_ta(_ta) \
	for (_ta = &__rodata_early_ta_start; _ta < &__rodata_early_ta_end; \
	     _ta = (const struct early_ta *)				   \
		   ROUNDUP((vaddr_t)_ta + sizeof(*_ta) + _ta->size,	   \
			   __alignof__(struct early_ta)))

#endif /* KERNEL_EARLY_TA_H */

