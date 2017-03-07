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
