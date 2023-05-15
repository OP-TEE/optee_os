/* SPDX-License-Identifier: BSD-2-Clause */
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

#include <compiler.h>
#include <kernel/msg_param.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <stdio.h>
#include <types_ext.h>

/**
 * msg_param_mobj_from_noncontig() - construct mobj from non-contiguous
 * list of pages.
 *
 * @buf_ptr - optee_msg_param.u.tmem.buf_ptr value
 * @size - optee_msg_param.u.tmem.size value
 * @shm_ref - optee_msg_param.u.tmem.shm_ref value
 * @map_buffer - true if buffer needs to be mapped into OP-TEE address space
 *
 * return:
 *	mobj or NULL on error
 */
#ifdef CFG_CORE_DYN_SHM
struct mobj *msg_param_mobj_from_noncontig(paddr_t buf_ptr, size_t size,
					   uint64_t shm_ref, bool map_buffer);
#else
static inline struct mobj *
msg_param_mobj_from_noncontig(paddr_t buf_ptr __unused, size_t size __unused,
			      uint64_t shm_ref __unused,
			      bool map_buffer __unused)
{
	return NULL;
}
#endif

/**
 * msg_param_attr_is_tmem - helper functions that cheks if attribute is tmem
 *
 * @attr - attribute to check
 *
 * return:
 *	corresponding size field
 */
static inline bool msg_param_attr_is_tmem(uint64_t attr)
{
	switch (attr & OPTEE_MSG_ATTR_TYPE_MASK) {
	case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
	case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
	case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
		return true;
	default:
		return false;
	}
}

#endif	/*KERNEL_MSG_PARAM_H*/
