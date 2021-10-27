/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#ifndef __TEE_RTI_CHECK_H
#define __TEE_RTI_CHECK_H

#include <types_ext.h>

#ifdef CFG_NS_RTI_CHECK
TEE_Result rti_check_add(paddr_t pa, size_t sz, bool final);
TEE_Result rti_check_rem(paddr_t pa, size_t sz);
TEE_Result rti_check_run(void);
#else
static inline TEE_Result rti_check_add(paddr_t pa __unused, size_t sz __unused,
				       bool final __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result rti_check_rem(paddr_t pa __unused, size_t sz __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result rti_check_run(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*CFG_NS_RTI_CHECK*/

#endif /*__TEE_RTI_CHECK_H*/
