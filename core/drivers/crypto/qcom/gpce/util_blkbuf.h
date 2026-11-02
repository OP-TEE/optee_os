/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * Block input buffering definitions.
 */
#ifndef GPCE_UTIL_BLKBUF_H
#define GPCE_UTIL_BLKBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>

#define BLK_BUF_IS_CTX_VALID(buf) ((buf) != NULL)

typedef TEE_Result (*blk_buf_out_op_cb)(void *ctx, const uint8_t *ibuf,
				 size_t isz, bool first, bool last);

struct Blk_buf_s {
	uint8_t *blk_buf;
	uint16_t buf_sz;
	uint16_t blk_sz;
	uint16_t sz;
	bool first;
	blk_buf_out_op_cb out_cb;
	void *ctx;
};

struct Blk_buf_s *util_blk_buf_new(void);
TEE_Result util_blk_buf_reset(struct Blk_buf_s *h);
TEE_Result util_blk_buf_free(struct Blk_buf_s *h);
TEE_Result util_blk_buf_init(struct Blk_buf_s *h, size_t blk_sz,
			     blk_buf_out_op_cb out_cb, void *ctx);
TEE_Result util_blk_buf_out(struct Blk_buf_s *h,
			    const uint8_t *ibuf, size_t isz);
TEE_Result util_blk_buf_copy(struct Blk_buf_s *dest_handle,
			     struct Blk_buf_s *src_handle, void *ctx);

#endif /* GPCE_UTIL_BLKBUF_H */
