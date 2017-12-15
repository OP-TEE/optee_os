/* SPDX-License-Identifier: BSD-2-Clause */
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
#ifndef TEE_API_PRIVATE
#define TEE_API_PRIVATE

#include <tee_api_types.h>
#include <utee_types.h>


void __utee_from_attr(struct utee_attribute *ua, const TEE_Attribute *attrs,
			uint32_t attr_count);

void __utee_from_param(struct utee_params *up, uint32_t param_types,
			const TEE_Param params[TEE_NUM_PARAMS]);

void __utee_to_param(TEE_Param params[TEE_NUM_PARAMS],
			uint32_t *param_types, const struct utee_params *up);

void __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id);


#if defined(CFG_TA_GPROF_SUPPORT)
void __utee_gprof_init(void);
void __utee_gprof_fini(void);
#else
static inline void __utee_gprof_init(void) {}
static inline void __utee_gprof_fini(void) {}
#endif

#endif /*TEE_API_PRIVATE*/

