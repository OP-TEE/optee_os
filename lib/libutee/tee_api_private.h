/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
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

