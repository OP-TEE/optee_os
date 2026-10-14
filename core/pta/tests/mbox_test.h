/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026, STMicroelectronics
 */
#ifndef CORE_PTA_TESTS_MBOX_H
#define CORE_PTA_TESTS_MBOX_H

#include <compiler.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

/* basic run-time tests */
#if defined(CFG_MBOX_TEST)
/* basic run-time tests */
TEE_Result core_mbox_tests(uint32_t ptypes,
			   TEE_Param params[TEE_NUM_PARAMS]);
#else
static inline TEE_Result core_mbox_tests(uint32_t ptypes __unused,
					 TEE_Param p[TEE_NUM_PARAMS] __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /*CORE_PTA_TESTS_MBOX_H*/
