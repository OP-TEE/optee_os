/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <string.h>
#include <kernel/tee_compat.h>

TEE_Result tee_compat_param_old_to_new(TEE_Operation *op,
				       struct tee_ta_param *param)
{
	size_t n;
	uint32_t pt;

	memset(param, 0, sizeof(*param));

	for (n = 0; n < 4; n++) {
		if (op->flags & 1 << n) {
			switch (op->memRefs[n].flags) {
			case TEE_MEM_INPUT:
				pt = TEE_PARAM_TYPE_MEMREF_INPUT;
				break;
			case TEE_MEM_OUTPUT:
				pt = TEE_PARAM_TYPE_MEMREF_OUTPUT;
				break;
			case TEE_MEM_INPUT | TEE_MEM_OUTPUT:
				pt = TEE_PARAM_TYPE_MEMREF_INOUT;
				break;
			default:
				return TEE_ERROR_BAD_PARAMETERS;
			}
			param->types |= pt << (n * 4);
			param->params[n].memref.buffer = op->memRefs[n].buffer;
			param->params[n].memref.size = op->memRefs[n].size;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result tee_compat_param_new_to_old(const struct tee_ta_param *param,
				       TEE_Operation *op)
{
	size_t n;

	op->flags = 0;
	for (n = 0; n < 4; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_NONE:
			continue;

		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			return TEE_ERROR_BAD_PARAMETERS; /* Not supported */

		case TEE_PARAM_TYPE_MEMREF_INPUT:
			op->memRefs[n].flags = TEE_MEM_INPUT;
			break;

		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			op->memRefs[n].flags = TEE_MEM_OUTPUT;
			break;

		case TEE_PARAM_TYPE_MEMREF_INOUT:
			op->memRefs[n].flags = TEE_MEM_INPUT | TEE_MEM_OUTPUT;
			break;

		default:
			return TEE_ERROR_BAD_PARAMETERS; /* Not supported */
		}

		op->flags |= 1 << n;
		op->memRefs[n].buffer = param->params[n].memref.buffer;
		op->memRefs[n].size = param->params[n].memref.size;
	}

	return TEE_SUCCESS;
}
