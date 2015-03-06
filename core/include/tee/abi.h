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
#ifndef TEE_ABI_H
#define TEE_ABI_H

#include <types_ext.h>
#include <tee_api_types.h>

/*
 * This file defines types specific to the ABI (Application Binary
 * Interface) provided by TEE Core. More types than those below are used,
 * but when they differ between 64-bit and 32-bit they are added in this
 * file.
 */


/* Defines parameters for 32-bit user TAs */
struct abi_user32_param {
	union {
		struct {
			uint32_t buf_ptr;
			uint32_t size;
		} memref;
		struct {
			uint32_t a;
			uint32_t b;
		} value;
	} u[TEE_NUM_PARAMS];
};

void abi_param_to_user32_param(struct abi_user32_param *usr_param,
			const TEE_Param *param, uint32_t param_types);
void abi_user32_param_to_param(TEE_Param *param,
			const struct abi_user32_param *usr_param,
			uint32_t param_types);


/* Defines TEE_Attribute for 32-bit user TAs */
struct abi_user32_attribute {
	uint32_t attr_id;
	union {
		struct {
			uint32_t buf_ptr;
			uint32_t length;
		} ref;
		struct {
			uint32_t a;
			uint32_t b;
		} value;
	} u;
};

void abi_attr_to_user32_attr(struct abi_user32_attribute *usr_attr,
			const TEE_Attribute *attr, size_t num_attrs);
void abi_user_attr32_to_attr(TEE_Attribute *attr,
			const struct abi_user32_attribute *usr_attr,
			size_t num_attrs);

#endif /*TEE_ABI_H*/

