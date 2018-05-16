/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef CORE_SELF_TESTS_H
#define CORE_SELF_TESTS_H

#include <tee_api_types.h>
#include <tee_api_defines.h>

/* basic run-time tests */
TEE_Result core_self_tests(uint32_t nParamTypes,
			   TEE_Param pParams[TEE_NUM_PARAMS]);

TEE_Result core_fs_htree_tests(uint32_t nParamTypes,
			       TEE_Param pParams[TEE_NUM_PARAMS]);

TEE_Result core_mutex_tests(uint32_t nParamTypes,
			    TEE_Param pParams[TEE_NUM_PARAMS]);

#endif /*CORE_SELF_TESTS_H*/
