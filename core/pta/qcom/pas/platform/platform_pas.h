/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_PAS_H
#define PLATFORM_PAS_H

#include <kernel/pseudo_ta.h>

TEE_Result qcom_pas_is_supported(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_capabilities(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_init_image(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_mem_setup(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_shutdown(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_get_resource_table(uint32_t pt,
				       TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_set_remote_state(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result qcom_pas_auth_and_reset(uint32_t pt,
				   TEE_Param params[TEE_NUM_PARAMS]);
#endif

