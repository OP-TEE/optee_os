/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */
#ifndef __KERNEL_EMBEDDED_TS_H
#define __KERNEL_EMBEDDED_TS_H

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

struct ts_store_handle;

TEE_Result emb_ts_read(struct ts_store_handle *h, void *data_core,
		       void *data_user, size_t len);
void emb_ts_close(struct ts_store_handle *h);

TEE_Result emb_ts_open(const TEE_UUID *uuid,
		       struct ts_store_handle **h,
		       const struct embedded_ts* (*find_ts)
		       (const TEE_UUID *uuid));
TEE_Result emb_ts_get_size(const struct ts_store_handle *h, size_t *size);
TEE_Result emb_ts_get_tag(const struct ts_store_handle *h,
			  uint8_t *tag, unsigned int *tag_len);
#endif /* __KERNEL_EMBEDDED_TS_H */

