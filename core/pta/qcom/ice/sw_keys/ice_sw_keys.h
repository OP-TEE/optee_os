/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __ICE_SW_KEYS_H
#define __ICE_SW_KEYS_H

#include <tee_api_types.h>

#include "../config.h"

TEE_Result sw_cmd_ice_invalidate_key(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result sw_cmd_ice_set_config_key(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS]);

#endif /* __ICE_SW_KEYS_H */
