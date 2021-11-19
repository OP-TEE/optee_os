/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef CORE_PTA_TESTS_MISC_H
#define CORE_PTA_TESTS_MISC_H

#include <compiler.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>

/* basic run-time tests */
TEE_Result core_self_tests(uint32_t nParamTypes,
			   TEE_Param pParams[TEE_NUM_PARAMS]);

TEE_Result core_fs_htree_tests(uint32_t nParamTypes,
			       TEE_Param pParams[TEE_NUM_PARAMS]);

TEE_Result core_mutex_tests(uint32_t nParamTypes,
			    TEE_Param pParams[TEE_NUM_PARAMS]);

#ifdef CFG_LOCKDEP
TEE_Result core_lockdep_tests(uint32_t nParamTypes,
			      TEE_Param pParams[TEE_NUM_PARAMS]);
#else
static inline TEE_Result core_lockdep_tests(
		uint32_t nParamTypes __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

TEE_Result core_aes_perf_tests(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result core_dt_driver_tests(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS]);

#endif /*CORE_PTA_TESTS_MISC_H*/
