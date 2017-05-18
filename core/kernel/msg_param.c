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

#include <optee_msg.h>
#include <stdio.h>
#include <types_ext.h>
#include <kernel/msg_param.h>
#include <mm/mobj.h>

/**
 * msg_param_extract_pages() - extract list of pages from
 * OPTEE_MSG_ATTR_TYPE_NONCONTIG buffer
 *
 * @buffer:	pointer to parameters array
 * @pages:	output array of page addresses
 * @num_pages:  number of pages in array
 *
 * return:
 *   page count on success
 *   <0 on error
 */
ssize_t msg_param_extract_pages(paddr_t buffer, paddr_t *pages,
				size_t num_pages)
{
	size_t cnt;
	struct mobj *mobj;
	paddr_t page;
	uint64_t *va;

	if (buffer & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;
	/* mobj_mapped_shm_alloc will check if page resides in nonsec ddr */
	mobj = mobj_mapped_shm_alloc(&buffer, 1, 0, 0);
	if (!mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	va = mobj_get_va(mobj, 0);
	assert(va);

	for (cnt = 0; cnt < num_pages; cnt++, va++) {
		/* if we are rolling over page boundary */
		if (!((vaddr_t)(va + 1) & SMALL_PAGE_MASK)) {
			page = *va;

			mobj_free(mobj);

			if (page & SMALL_PAGE_MASK)
				return TEE_ERROR_BAD_PARAMETERS;

			mobj = mobj_mapped_shm_alloc(&page, 1, 0, 0);
			if (!mobj)
				return TEE_ERROR_BAD_PARAMETERS;

			va = mobj_get_va(mobj, 0);
			assert(va);
		}
		pages[cnt] = *va;
	}

	mobj_free(mobj);
	return cnt;
}

/**
 * msg_param_init_memparam() - fill memory reference parameter for RPC call
 * @param	- parameter to fill
 * @mobj	- mobj describing the shared memory buffer
 * @offset	- offset of the buffer
 * @size	- size of the buffer
 * @cookie	- NW cookie of the shared buffer
 * @dir		- data direction
 *
 * Idea behind this function is that thread_rpc_alloc() can return
 * either buffer from preallocated memory pool, of buffer constructed
 * from supplicant's memory. In first case parameter will have type
 * OPTEE_MSG_ATTR_TYPE_TMEM_* and OPTEE_MSG_ATTR_TYPE_RMEM_ in second case.
 * This function will fill parameter structure with right type, depending on
 * the passed mobj.
 *
 * return:
 *	true on success, false on failure
 */
bool msg_param_init_memparam(struct optee_msg_param *param, struct mobj *mobj,
			     size_t offset, size_t size,
			     uint64_t cookie, enum msg_param_mem_dir dir)
{
	if (mobj_matches(mobj, CORE_MEM_REG_SHM)) {
		/* Registered SHM mobj */
		switch (dir) {
		case MSG_PARAM_MEM_DIR_IN:
			param->attr = OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
			break;
		case MSG_PARAM_MEM_DIR_OUT:
			param->attr = OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT;
			break;
		case MSG_PARAM_MEM_DIR_INOUT:
			param->attr = OPTEE_MSG_ATTR_TYPE_RMEM_INOUT;
			break;
		default:
			return false;
		}

		param->u.rmem.size = size;
		param->u.rmem.offs = offset;
		param->u.rmem.shm_ref = cookie;
	} else if (mobj_matches(mobj, CORE_MEM_NSEC_SHM)) {
		/* MOBJ from from predefined pool */
		paddr_t pa;

		if (mobj_get_pa(mobj, 0, 0, &pa) != TEE_SUCCESS)
			return false;

		switch (dir) {
		case MSG_PARAM_MEM_DIR_IN:
			param->attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			break;
		case MSG_PARAM_MEM_DIR_OUT:
			param->attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
			break;
		case MSG_PARAM_MEM_DIR_INOUT:
			param->attr = OPTEE_MSG_ATTR_TYPE_TMEM_INOUT;
			break;
		default:
			return false;
		}

		param->u.tmem.buf_ptr = pa + offset;
		param->u.tmem.shm_ref = cookie;
		param->u.tmem.size = size;
	} else
		return false;
	return true;
}
