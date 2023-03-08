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
#define TEE_AEDecryptFinal __GP11_TEE_AEDecryptFinal
#define TEE_AEEncryptFinal __GP11_TEE_AEEncryptFinal
#define TEE_AEInit __GP11_TEE_AEInit
#define TEE_AEUpdateAAD __GP11_TEE_AEUpdateAAD
#define TEE_AEUpdate __GP11_TEE_AEUpdate
#define TEE_AllocateTransientObject __GP11_TEE_AllocateTransientObject
#define TEE_AsymmetricDecrypt __GP11_TEE_AsymmetricDecrypt
#define TEE_AsymmetricEncrypt __GP11_TEE_AsymmetricEncrypt
#define TEE_AsymmetricSignDigest __GP11_TEE_AsymmetricSignDigest
#define TEE_AsymmetricVerifyDigest __GP11_TEE_AsymmetricVerifyDigest
#define TEE_BigIntConvertFromOctetString __GP11_TEE_BigIntConvertFromOctetString
#define TEE_BigIntConvertToOctetString __GP11_TEE_BigIntConvertToOctetString
#define TEE_BigIntFMMContextSizeInU32 __GP11_TEE_BigIntFMMContextSizeInU32
#define TEE_BigIntFMMSizeInU32 __GP11_TEE_BigIntFMMSizeInU32
#define TEE_BigIntInitFMMContext __GP11_TEE_BigIntInitFMMContext
#define TEE_BigIntInitFMM __GP11_TEE_BigIntInitFMM
#define TEE_BigIntShiftRight __GP11_TEE_BigIntShiftRight
#define TEE_CheckMemoryAccessRights __GP11_TEE_CheckMemoryAccessRights
#define TEE_CipherDoFinal __GP11_TEE_CipherDoFinal
#define TEE_CipherInit __GP11_TEE_CipherInit
#define TEE_CipherUpdate __GP11_TEE_CipherUpdate
#define TEE_CreatePersistentObject __GP11_TEE_CreatePersistentObject
#define TEE_DeriveKey __GP11_TEE_DeriveKey
#define TEE_DigestDoFinal __GP11_TEE_DigestDoFinal
#define TEE_DigestUpdate __GP11_TEE_DigestUpdate
#define TEE_FreeOperation __GP11_TEE_FreeOperation
#define TEE_GenerateKey __GP11_TEE_GenerateKey
#define TEE_GenerateRandom __GP11_TEE_GenerateRandom
#define TEE_GetNextPersistentObject __GP11_TEE_GetNextPersistentObject
#define TEE_GetObjectBufferAttribute __GP11_TEE_GetObjectBufferAttribute
#define TEE_GetObjectInfo1 __GP11_TEE_GetObjectInfo1
#define TEE_GetObjectInfo __GP11_TEE_GetObjectInfo
#define TEE_GetOperationInfoMultiple __GP11_TEE_GetOperationInfoMultiple
#define TEE_GetPropertyAsBinaryBlock __GP11_TEE_GetPropertyAsBinaryBlock
#define TEE_GetPropertyAsString __GP11_TEE_GetPropertyAsString
#define TEE_GetPropertyName __GP11_TEE_GetPropertyName
#define TEE_InitRefAttribute __GP11_TEE_InitRefAttribute
#define TEE_InitValueAttribute __GP11_TEE_InitValueAttribute
#define TEE_InvokeTACommand __GP11_TEE_InvokeTACommand
#define TEE_MACCompareFinal __GP11_TEE_MACCompareFinal
#define TEE_MACComputeFinal __GP11_TEE_MACComputeFinal
#define TEE_MACInit __GP11_TEE_MACInit
#define TEE_MACUpdate __GP11_TEE_MACUpdate
#define TEE_Malloc __GP11_TEE_Malloc
#define TEE_MemCompare __GP11_TEE_MemCompare
#define TEE_MemFill __GP11_TEE_MemFill
#define TEE_MemMove __GP11_TEE_MemMove
#define TEE_OpenPersistentObject __GP11_TEE_OpenPersistentObject
#define TEE_OpenTASession __GP11_TEE_OpenTASession
#define TEE_PopulateTransientObject __GP11_TEE_PopulateTransientObject
#define TEE_ReadObjectData __GP11_TEE_ReadObjectData
#define TEE_Realloc __GP11_TEE_Realloc
#define TEE_RenamePersistentObject __GP11_TEE_RenamePersistentObject
#define TEE_SeekObjectData __GP11_TEE_SeekObjectData
#define TEE_SetOperationKey2 __GP11_TEE_SetOperationKey2
#define TEE_SetOperationKey __GP11_TEE_SetOperationKey
#define TEE_TruncateObjectData __GP11_TEE_TruncateObjectData
#define TEE_WriteObjectData __GP11_TEE_WriteObjectData
#endif

#endif /*__TEE_API_COMPAT_H*/
