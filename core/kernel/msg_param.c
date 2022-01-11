// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, EPAM Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <kernel/msg_param.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <stdio.h>
#include <types_ext.h>
#include <util.h>

/**
 * msg_param_extract_pages() - extract list of pages from
 * OPTEE_MSG_ATTR_NONCONTIG buffer.
 *
 * @buffer:	pointer to parameters array
 * @pages:	output array of page addresses
 * @num_pages:  number of pages in array
 *
 * return:
 *	true on success, false otherwise
 *
 * @buffer points to the physical address of a structure that can be viewed as
 *
 * struct page_data {
 *   uint64_t pages_array[OPTEE_MSG_NONCONTIG_PAGE_SIZE/sizeof(uint64_t) - 1];
 *   uint64_t next_page_data;
 * };
 *
 * So, it is a linked list of arrays, where each element of linked list fits
 * exactly into one 4K page.
 *
 * This function extracts data from arrays into one array pointed by @pages
 *
 * @buffer points to data shared with normal world, so some precautions
 * should be taken.
 */
static bool msg_param_extract_pages(paddr_t buffer, paddr_t *pages,
				       size_t num_pages)
{
	size_t cnt;
	struct mobj *mobj;
	paddr_t page;
	uint64_t *va;
	bool ret = false;

	if (buffer & SMALL_PAGE_MASK)
		return false;

	/*
	 * There we map first page of array.
	 * mobj_mapped_shm_alloc() will check if page resides in nonsec ddr
	 */
	mobj = mobj_mapped_shm_alloc(&buffer, 1, 0, 0);
	if (!mobj)
		return false;

	va = mobj_get_va(mobj, 0, SMALL_PAGE_SIZE);
	assert(va);

	for (cnt = 0; cnt < num_pages; cnt++, va++) {
		/*
		 * If we about to roll over page boundary, then last entry holds
		 * address of next page of array. Unmap current page and map
		 * next one
		 */
		if (!((vaddr_t)(va + 1) & SMALL_PAGE_MASK)) {
			page = *va;
			if (page & SMALL_PAGE_MASK)
				goto out;

			mobj_put(mobj);
			mobj = mobj_mapped_shm_alloc(&page, 1, 0, 0);
			if (!mobj)
				goto out;

			va = mobj_get_va(mobj, 0, SMALL_PAGE_SIZE);
			assert(va);
		}
		pages[cnt] = *va;
		if (pages[cnt] & SMALL_PAGE_MASK)
			goto out;
	}

	ret = true;
out:
	mobj_put(mobj);
	return ret;
}

struct mobj *msg_param_mobj_from_noncontig(paddr_t buf_ptr, size_t size,
					   uint64_t shm_ref, bool map_buffer)
{
	struct mobj *mobj = NULL;
	paddr_t *pages = NULL;
	paddr_t page_offset = 0;
	size_t num_pages = 0;
	size_t size_plus_offs = 0;
	size_t msize = 0;

	page_offset = buf_ptr & SMALL_PAGE_MASK;
	if (ADD_OVERFLOW(size, page_offset, &size_plus_offs))
		return NULL;
	num_pages = (size_plus_offs - 1) / SMALL_PAGE_SIZE + 1;
	if (MUL_OVERFLOW(num_pages, sizeof(paddr_t), &msize))
		return NULL;

	pages = malloc(msize);
	if (!pages)
		return NULL;

	if (!msg_param_extract_pages(buf_ptr & ~SMALL_PAGE_MASK,
				     pages, num_pages))
		goto out;

	if (map_buffer)
		mobj = mobj_mapped_shm_alloc(pages, num_pages, page_offset,
					     shm_ref);
	else
		mobj = mobj_reg_shm_alloc(pages, num_pages, page_offset,
					  shm_ref);
out:
	free(pages);
	return mobj;
}
