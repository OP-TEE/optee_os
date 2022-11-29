/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __TEE_API_COMPAT_H
#define __TEE_API_COMPAT_H

#if __OPTEE_CORE_API_COMPAT_1_1
/* Types */
#define TEE_Attribute __GP11_TEE_Attribute
#define TEE_ObjectInfo __GP11_TEE_ObjectInfo

/* Functions */
#define TEE_AsymmetricDecrypt __GP11_TEE_AsymmetricDecrypt
#define TEE_AsymmetricEncrypt __GP11_TEE_AsymmetricEncrypt
#define TEE_AsymmetricSignDigest __GP11_TEE_AsymmetricSignDigest
#define TEE_AsymmetricVerifyDigest __GP11_TEE_AsymmetricVerifyDigest
#define TEE_DeriveKey __GP11_TEE_DeriveKey
#define TEE_GenerateKey __GP11_TEE_GenerateKey
#define TEE_GetNextPersistentObject __GP11_TEE_GetNextPersistentObject
#define TEE_GetObjectInfo1 __GP11_TEE_GetObjectInfo1
#define TEE_GetObjectInfo __GP11_TEE_GetObjectInfo
#define TEE_InitRefAttribute __GP11_TEE_InitRefAttribute
#define TEE_InitValueAttribute __GP11_TEE_InitValueAttribute
#define TEE_PopulateTransientObject __GP11_TEE_PopulateTransientObject
#endif

#endif /*__TEE_API_COMPAT_H*/
