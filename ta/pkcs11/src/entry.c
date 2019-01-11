// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <compiler.h>
#include <tee_internal_api.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **session)
{
	*session = NULL;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session __unused)
{
}

/*
 * Entry point for PKCS11 TA commands
 */
TEE_Result TA_InvokeCommandEntryPoint(void *tee_session __unused, uint32_t cmd,
				      uint32_t ptypes __unused,
				      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	EMSG("Command 0x%"PRIx32" is not supported", cmd);

	return TEE_ERROR_NOT_SUPPORTED;
}
