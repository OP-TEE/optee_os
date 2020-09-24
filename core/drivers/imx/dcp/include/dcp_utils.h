/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __DCP_UTILS_H__
#define __DCP_UTILS_H__

#include <drivers/imx/dcp.h>
#include <types_ext.h>

/* Adjust index value for writing in register */
#define DCP_SRAM_KEY_INDEX(idx) SHIFT_U32(idx, 4)

/* Calculate context switching buffer offset */
#define DCP_CONTEXT_SW_OFFSET(chann) ((DCP_NB_CHANNELS - 1 - (chann)) * 52)

/*
 * Allocate internal driver buffer aligned with a cache line and initialize it
 * with 0s
 *
 * @buf   [out] Buffer to allocate
 * @size  Size in bytes of the memory to allocate
 */
TEE_Result dcp_calloc_align_buf(struct dcp_align_buf *buf, size_t size);

/*
 * Free allocated memory
 *
 * @buf  buffer to free.
 */
void dcp_free(struct dcp_align_buf *buf);

/*
 * Left shifting a multi bytes buffer by one bit
 *
 * @result       [out] Buffer containing the result of the operation
 * @input        Input buffer for the operation
 * @buffer_size  Size of the buffer in bytes
 */
void dcp_left_shift_buffer(uint8_t *result, uint8_t *input, size_t buffer_size);

/*
 * Wait given microsecond
 *
 * @time   Time in microsecond
 */
void dcp_udelay(uint32_t time);

/*
 * Copies elements from a buffer to another one. These elements are copied in
 * reverse order.
 *
 * @in     input buffer
 * @out    output buffer
 * @size   bytes to copy
 */
void dcp_reverse(uint8_t *in, uint8_t *out, size_t size);

/*
 * Operate a XOR between two same size buffers
 *
 * @a    Input buffer to XOR
 * @b    Input buffer to XOR
 * @out  Result of the XOR operation
 * @size Size of input and output buffers
 */
void dcp_xor(uint8_t *a, uint8_t *b, uint8_t *out, size_t size);

/*
 * CMAC padding.
 * The padding result is the concatenation of the input buffer block and a
 * single '1' followed by the minimum number of '0's to get a 128 bits
 * block.
 *
 * @block Block to pad
 * @len   Length of the padding
 */
void dcp_cmac_padding(uint8_t *block, size_t len);

#endif /* __DCP_UTILS_H__ */
