/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __TEE_API_COMPAT_H
#define __TEE_API_COMPAT_H

/*
 * This function will be called from TA_OpenSessionEntryPoint() in
 * user_ta_header.c (if compiled with __OPTEE_CORE_API_COMPAT_1_1), the
 * compatibility entry function is passed as a function pointer in @fp.
 * This is needed since libutee is never compiled with
 * __OPTEE_CORE_API_COMPAT_1_1, but we still need a way to call the
 * compatibility function __GP11_TA_InvokeCommandEntryPoint(), but only
 * when __OPTEE_CORE_API_COMPAT_1_1 is defined.
 */
TEE_Result __ta_open_sess(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS],
			  void **sess_ctx,
			  TEE_Result (*fp)(uint32_t,
					   __GP11_TEE_Param [TEE_NUM_PARAMS],
					   void **));

/*
 * Same as for __ta_open_sess_func(), except that @fp now is a pointer to
 * __GP11_TA_InvokeCommandEntryPoint().
 */
TEE_Result __ta_invoke_cmd(void *sess_ctx, uint32_t cmd_id, uint32_t pt,
			   TEE_Param params[TEE_NUM_PARAMS],
			   TEE_Result (*fp)(void *, uint32_t, uint32_t,
					    __GP11_TEE_Param [TEE_NUM_PARAMS]));

#if __OPTEE_CORE_API_COMPAT_1_1
/* Types */
#define TEE_Attribute __GP11_TEE_Attribute
#define TEE_ObjectInfo __GP11_TEE_ObjectInfo
#define TEE_Param __GP11_TEE_Param

/* Functions */
#define TA_InvokeCommandEntryPoint __GP11_TA_InvokeCommandEntryPoint
#define TA_OpenSessionEntryPoint __GP11_TA_OpenSessionEntryPoint
#define TEE_AsymmetricDecrypt __GP11_TEE_AsymmetricDecrypt
#define TEE_AsymmetricEncrypt __GP11_TEE_AsymmetricEncrypt
#define TEE_AsymmetricSignDigest __GP11_TEE_AsymmetricSignDigest
#define TEE_AsymmetricVerifyDigest __GP11_TEE_AsymmetricVerifyDigest
#define TEE_CheckMemoryAccessRights __GP11_TEE_CheckMemoryAccessRights
#define TEE_DeriveKey __GP11_TEE_DeriveKey
#define TEE_GenerateKey __GP11_TEE_GenerateKey
#define TEE_GetNextPersistentObject __GP11_TEE_GetNextPersistentObject
#define TEE_GetObjectInfo1 __GP11_TEE_GetObjectInfo1
#define TEE_GetObjectInfo __GP11_TEE_GetObjectInfo
#define TEE_GetPropertyAsBinaryBlock __GP11_TEE_GetPropertyAsBinaryBlock
#define TEE_GetPropertyAsString __GP11_TEE_GetPropertyAsString
#define TEE_GetPropertyName __GP11_TEE_GetPropertyName
#define TEE_InitRefAttribute __GP11_TEE_InitRefAttribute
#define TEE_InitValueAttribute __GP11_TEE_InitValueAttribute
#define TEE_InvokeTACommand __GP11_TEE_InvokeTACommand
#define TEE_Malloc __GP11_TEE_Malloc
#define TEE_MemCompare __GP11_TEE_MemCompare
#define TEE_MemFill __GP11_TEE_MemFill
#define TEE_MemMove __GP11_TEE_MemMove
#define TEE_OpenTASession __GP11_TEE_OpenTASession
#define TEE_PopulateTransientObject __GP11_TEE_PopulateTransientObject
#define TEE_Realloc __GP11_TEE_Realloc
#endif

#endif /*__TEE_API_COMPAT_H*/
