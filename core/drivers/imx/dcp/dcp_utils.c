// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */
#include <dcp_utils.h>
#include <drivers/imx/dcp.h>
#include <kernel/cache_helpers.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <trace.h>

/*
 * Allocate an area of given size in bytes and set it to zero. Add the memory
 * allocator information in the newly allocated area.
 * Return a cacheline aligned buffer.
 *
 * @size   Size in bytes to allocate
 */
static void *dcp_alloc_memalign(size_t size)
{
	void *ptr = NULL;
	size_t alloc_size = 0;
	uint32_t cacheline_size = 0;

	/*
	 * Buffer must be aligned on a cache line:
	 *  - Buffer start address aligned on a cache line
	 *  - End of Buffer inside a cache line.
	 *
	 * If the size to be allocated is already aligned on a cache line add a
	 * another cache line.
	 */
	cacheline_size = dcache_get_line_size();
	if (ROUNDUP_OVERFLOW(size, cacheline_size, &alloc_size))
		return NULL;

	ptr = memalign(cacheline_size, alloc_size);
	if (!ptr)
		return NULL;

	memset(ptr, 0, size);

	return ptr;
}

TEE_Result dcp_calloc_align_buf(struct dcp_align_buf *buf, size_t size)
{
	if (!buf) {
		EMSG("Error, buf is null");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	buf->data = dcp_alloc_memalign(size);
	if (!buf->data)
		return TEE_ERROR_OUT_OF_MEMORY;

	buf->paddr = virt_to_phys(buf->data);

	if (!buf->paddr) {
		dcp_free(buf);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	buf->size = size;

	return TEE_SUCCESS;
}

void dcp_free(struct dcp_align_buf *buf)
{
	free(buf->data);
}

void dcp_left_shift_buffer(uint8_t *input, uint8_t *result, size_t buffer_size)
{
	unsigned int i = 0;
	uint8_t overflow = 0;

	/* For each byte */
	for (i = 0; i < buffer_size; i++) {
		/* Left shift a bytes by one */
		result[buffer_size - 1 - i] =
			input[buffer_size - 1 - i] << 1 | overflow;

		overflow = input[buffer_size - 1 - i] >> 7;
	}
}

void dcp_udelay(uint32_t time)
{
	uint32_t counter = time * 500;

	/* Implementation of a Software loop assuming CPU clock of 500MHz */
	while (counter--) {
		isb();
		dsb();
	};
}

void dcp_reverse(uint8_t *in, uint8_t *out, size_t size)
{
	unsigned int i = 0;

	for (i = 0; i < size; i++)
		out[i] = in[size - 1 - i];
}

void dcp_xor(uint8_t *a, uint8_t *b, uint8_t *out, size_t size)
{
	unsigned int i = 0;

	for (i = 0; i < size; i++)
		out[i] = a[i] ^ b[i];
}

void dcp_cmac_padding(uint8_t *block, size_t len)
{
	unsigned int i = 0;

	for (i = len; i < DCP_AES128_BLOCK_SIZE; i++) {
		if (i == len)
			block[i] = BIT(7);
		else
			block[i] = 0x0;
	}
}
