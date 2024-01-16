/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#ifndef __TEE_TEE_SUPP_PLUGIN_RPC_H
#define __TEE_TEE_SUPP_PLUGIN_RPC_H

#include <stdint.h>
#include <stdbool.h>
#include <tee_api_types.h>

TEE_Result tee_invoke_supp_plugin_rpc(const TEE_UUID *uuid, uint32_t cmd,
				      uint32_t sub_cmd, void *buf_core,
				      void *buf_user, size_t len,
				      size_t *outlen);

#endif /* __TEE_TEE_SUPP_PLUGIN_RPC_H */
