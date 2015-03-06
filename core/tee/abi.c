/*
 * Copyright (c) 2015, Linaro Limited
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

#include <tee/abi.h>

void abi_param_to_user32_param(struct abi_user32_param *usr_param,
			const TEE_Param *param, uint32_t param_types)
{
	size_t n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			usr_param->u[n].memref.buf_ptr =
				(uintptr_t)param[n].memref.buffer;
			usr_param->u[n].memref.size = param[n].memref.size;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			usr_param->u[n].value.a = param[n].value.a;
			usr_param->u[n].value.b = param[n].value.b;
		default:
			break;
		}
	}
}

void abi_user32_param_to_param(TEE_Param *param,
			const struct abi_user32_param *usr_param,
			uint32_t param_types)
{
	size_t n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			param[n].memref.buffer = (void *)(uintptr_t)
					usr_param->u[n].memref.buf_ptr;
			param[n].memref.size = usr_param->u[n].memref.size;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			param[n].value.a = usr_param->u[n].value.a;
			param[n].value.b = usr_param->u[n].value.b;
		default:
			break;
		}
	}
}

void abi_attr_to_user32_attr(struct abi_user32_attribute *usr_attr,
			const TEE_Attribute *attr, size_t num_attrs)
{
	size_t n;

	for (n = 0; n < num_attrs; n++) {
		usr_attr[n].attr_id = attr[n].attributeID;
		if (attr[n].attributeID & TEE_ATTR_BIT_VALUE) {
			usr_attr[n].u.value.a = attr[n].content.value.a;
			usr_attr[n].u.value.b = attr[n].content.value.b;
		} else {
			usr_attr[n].u.ref.buf_ptr =
				(uintptr_t)attr[n].content.ref.buffer;
			usr_attr[n].u.ref.length = attr[n].content.ref.length;
		}
	}
}

void abi_user_attr32_to_attr(TEE_Attribute *attr,
			const struct abi_user32_attribute *usr_attr,
			size_t num_attrs)
{
	size_t n;

	for (n = 0; n < num_attrs; n++) {
		attr[n].attributeID = usr_attr[n].attr_id;
		if (usr_attr[n].attr_id & TEE_ATTR_BIT_VALUE) {
			attr[n].content.value.a = usr_attr[n].u.value.a;
			attr[n].content.value.b = usr_attr[n].u.value.b;
		} else {
			attr[n].content.ref.buffer = (void *)(uintptr_t)
						     usr_attr[n].u.ref.buf_ptr;
			attr[n].content.ref.length = usr_attr[n].u.ref.length;
		}
	}
}
