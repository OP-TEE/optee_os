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

#ifndef KERNEL_MSG_PARAM_H
#define KERNEL_MSG_PARAM_H

#include <optee_msg.h>
#include <stdio.h>
#include <types_ext.h>
#include <kernel/msg_param.h>
#include <mm/mobj.h>

/*
 * This enum is used in tee_fill_memparam(). It describes direction of memory
 * parameter.
 */
enum msg_param_mem_dir {
	MSG_PARAM_MEM_DIR_IN = 0,
	MSG_PARAM_MEM_DIR_OUT,
	MSG_PARAM_MEM_DIR_INOUT,
};

/**
 * msg_param_mobj_from_noncontig() - construct mobj from non-contiguous
 * list of pages.
 *
 * @param - pointer to msg_param with OPTEE_MSG_ATTR_NONCONTIG flag set
 * @map_buffer - true if buffer needs to be mapped into OP-TEE address space
 *
 * return:
 *	mobj or NULL on error
 */
struct mobj *msg_param_mobj_from_noncontig(const struct optee_msg_param *param,
					   bool map_buffer);

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
			     uint64_t cookie, enum msg_param_mem_dir dir);
/**
 * msg_param_get_buf_size() - helper functions that reads [T/R]MEM
 *			      parameter size
 *
 * @param - struct optee_msg_param to read size from
 *
 * return:
 *	corresponding size field
 */
static inline size_t msg_param_get_buf_size(const struct optee_msg_param *param)
{
	switch (param->attr & OPTEE_MSG_ATTR_TYPE_MASK) {
	case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
	case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
	case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
		return param->u.tmem.size;
	case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
	case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
	case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
		return param->u.rmem.size;
	default:
		return 0;
	}
}

/**
 * msg_param_attr_is_tmem - helper functions that cheks if parameter is tmem
 *
 * @param - struct optee_msg_param to check
 *
 * return:
 *	corresponding size field
 */
static inline bool msg_param_attr_is_tmem(const struct optee_msg_param *param)
{
	switch (param->attr & OPTEE_MSG_ATTR_TYPE_MASK) {
	case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
	case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
	case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
		return true;
	default:
		return false;
	}
}

#endif	/*KERNEL_MSG_PARAM_H*/
