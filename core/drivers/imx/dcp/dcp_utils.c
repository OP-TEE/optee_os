// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */
#include <dcp_utils.h>
#include <drivers/imx/dcp.h>
#include <kernel/cache_helpers.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <trace.h>

struct __packed mem_hdr {
	void *addr;
	size_t size;
};

#define MEM_HDR_SIZE  ROUNDUP(sizeof(struct mem_hdr), sizeof(void *))
#define OF_MEM_HDR(p) (struct mem_hdr *)((uint8_t *)(p) - (MEM_HDR_SIZE))

/*
 * Allocate an area of given size in bytes and set it to zero. Add the memory
 * allocator information in the newly allocated area.
 * Return a cacheline aligned buffer.
 *
 * @size   Size in bytes to allocate
 */
static void *dcp_alloc_memalign(size_t size)
{
	struct mem_hdr *hdr = NULL;
	vaddr_t ret_addr = 0;
	void *ptr = NULL;
	size_t alloc_size = 0;
	uint32_t cacheline_size = 0;

	/*
	 * The mem_hdr header is added just before the returned
	 * buffer address
	 *
	 * --------------
	 * |  mem_hdr   |
	 * --------------
	 * |  Buffer    |
	 * --------------
	 */
	if (ADD_OVERFLOW(size, MEM_HDR_SIZE, &alloc_size))
		return NULL;

	/*
	 * Buffer must be aligned on a cache line:
	 *  - Buffer start address aligned on a cache line
	 *  - End of Buffer inside a cache line.
	 *
	 * If area's (mem info + buffer) to be allocated size is
	 * already cache line aligned add a cache line.
	 *
	 * Because Buffer address returned is moved up to a cache
	 * line start offset, add a cache line to full area allocated
	 * to ensure that end of the working buffer is in a cache line.
	 */
	cacheline_size = dcache_get_line_size();
	if (size == cacheline_size) {
		if (ADD_OVERFLOW(alloc_size, cacheline_size, &alloc_size))
			return NULL;
	}

	if (ADD_OVERFLOW(cacheline_size, ROUNDUP(alloc_size, cacheline_size),
			 &alloc_size))
		return NULL;

	ptr = calloc(1, alloc_size);

	if (!ptr) {
		EMSG("alloc Error - NULL");
		return NULL;
	}

	/* Calculate the return buffer address */
	ret_addr = (vaddr_t)ptr + MEM_HDR_SIZE;
	ret_addr = ROUNDUP(ret_addr, cacheline_size);

	/* Add the mem_hdr header */
	hdr = OF_MEM_HDR(ret_addr);
	hdr->addr = ptr;
	hdr->size = alloc_size;

	return (void *)ret_addr;
}

/*
 * Free aligned allocated area
 *
 * @ptr   area to free
 */
static void dcp_free_memalign(void *ptr)
{
	if (ptr)
		free((OF_MEM_HDR(ptr))->addr);
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
	if (buf->data)
		dcp_free_memalign(buf->data);
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

	/* Implementation of a Software loop */
	while (counter--) {
		isb();
		dsb();
	};
}

void dcp_copy_backwards(uint8_t *in, uint8_t *out, size_t size)
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
