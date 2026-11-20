/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Block buffer helpers for Crypto Engine transfers.
 */
#ifndef QCOM_GPCE_UTIL_BLKBUF_H
#define QCOM_GPCE_UTIL_BLKBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

struct blk_buf;

/* Callback that submits a block-buffer transfer to the Crypto Engine. */
typedef TEE_Result (*blk_buf_out_cb)(void *ctx, const uint8_t *ibuf,
				     size_t isz, bool first, bool last);

/*
 * util_blk_buf_new() - Allocate a block-buffer handle
 *
 * Return: A new handle, or NULL on allocation failure.
 */
struct blk_buf *util_blk_buf_new(void);

/**
 * util_blk_buf_reset() - Discard buffered input and restart a transfer stream
 * @h: Block-buffer handle to reset
 *
 * Retains the configured callback and allocated buffer.
 *
 * Return: TEE_SUCCESS on success, or TEE_ERROR_BAD_PARAMETERS if @h is NULL.
 */
TEE_Result util_blk_buf_reset(struct blk_buf *h);

/**
 * util_blk_buf_free() - Wipe and release a block-buffer handle
 * @h: Block-buffer handle to release
 *
 * Return: TEE_SUCCESS on success, or TEE_ERROR_BAD_PARAMETERS if @h is NULL.
 */
TEE_Result util_blk_buf_free(struct blk_buf *h);

/**
 * util_blk_buf_size() - Return the number of bytes awaiting transfer
 * @h: Block-buffer handle
 *
 * Return: Number of buffered bytes, or zero if @h is NULL.
 */
size_t util_blk_buf_size(struct blk_buf *h);

/**
 * util_blk_buf_init() - Configure a block-buffer handle
 * @h: Block-buffer handle allocated with util_blk_buf_new()
 * @blk_sz: Hash block size used to divide input into transfer units
 * @min_hold_sz_req: Allocate space for an additional block to retain input
 * @out_cb: Callback that submits complete blocks; @first identifies the first
 *	 transfer and @last identifies the final transfer
 * @ctx: Caller context passed unchanged to @out_cb
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS for invalid input,
 * or TEE_ERROR_OUT_OF_MEMORY if the buffer allocation fails.
 */
TEE_Result util_blk_buf_init(struct blk_buf *h, size_t blk_sz,
			     bool min_hold_sz_req,
			     blk_buf_out_cb out_cb,
			     void *ctx);

/**
 * util_blk_buf_set_ctx() - Update the callback context for a block buffer
 * @h: Configured block-buffer handle
 * @ctx: Caller context passed to @out_cb
 *
 * Return: TEE_SUCCESS on success, or TEE_ERROR_BAD_PARAMETERS if @h is NULL.
 */
TEE_Result util_blk_buf_set_ctx(struct blk_buf *h, void *ctx);

/**
 * util_blk_buf_out() - Buffer input and submit complete blocks
 * @h: Configured block-buffer handle
 * @ibuf: Input buffer, or NULL to flush the final buffered bytes
 * @isz: Number of bytes in @ibuf; must be zero when @ibuf is NULL
 *
 * A NULL @ibuf flushes the remaining buffered bytes through the callback as
 * the final transfer.
 *
 * Return: TEE_SUCCESS on success or an error from argument validation or the
 * callback.
 */
TEE_Result util_blk_buf_out(struct blk_buf *h, const uint8_t *ibuf,
			    size_t isz);

/**
 * util_blk_buf_copy() - Copy buffered state to another handle
 * @dest_handle: Destination handle that receives a copy of @src_handle
 * @src_handle: Source handle to copy
 * @ctx: Caller context to use for the destination callback
 *
 * Allocates a separate data buffer for @dest_handle while copying the source
 * configuration and pending input.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS for an invalid
 * source or destination, or TEE_ERROR_OUT_OF_MEMORY on allocation failure.
 */
TEE_Result util_blk_buf_copy(struct blk_buf *dest_handle,
			     struct blk_buf *src_handle, void *ctx);

#endif /* QCOM_GPCE_UTIL_BLKBUF_H */
