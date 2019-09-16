/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __TEE_API_EXTENSIONS_H__
#define __TEE_API_EXTENSIONS_H__

/* System API - Internal Client API to invoke custom REE service */

TEE_Result TEE_OpenREESession(TEE_UUID *destination,
				uint32_t cancellationRequestTimeout,
				uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				ree_session_handle *session,
				uint32_t *returnOrigin);

void TEE_CloseREESession(ree_session_handle session);

TEE_Result TEE_InvokeREECommand(ree_session_handle session,
				uint32_t cancellationRequestTimeout,
				uint32_t commandID, uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				uint32_t *returnOrigin);

#endif
