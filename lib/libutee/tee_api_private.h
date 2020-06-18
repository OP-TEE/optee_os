/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2020, Linaro Limited
 */
#ifndef TEE_API_PRIVATE
#define TEE_API_PRIVATE

#include <tee_api_types.h>
#include <utee_types.h>


void __utee_from_attr(struct utee_attribute *ua, const TEE_Attribute *attrs,
			uint32_t attr_count);

TEE_Result __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id);


#if defined(CFG_TA_GPROF_SUPPORT)
void __utee_gprof_init(void);
void __utee_gprof_fini(void);
#else
static inline void __utee_gprof_init(void) {}
static inline void __utee_gprof_fini(void) {}
#endif

/*
 * The functions help checking that the pointers comply with the parameters
 * annotation as described in the spec. Any descrepency results in a panic
 * of the TA.
 */
void __utee_check_out_annotation(void *buf, const size_t len);
void __utee_check_inout_annotation(void *buf, const size_t len);
void __utee_check_attr_in_annotation(const TEE_Attribute *attr, size_t count);
void __utee_check_outbuf_annotation(void *buf, uint32_t *len);
void __utee_check_instring_annotation(const char *buf);
void __utee_check_outstring_annotation(char *buf, uint32_t *len);

#endif /*TEE_API_PRIVATE*/
