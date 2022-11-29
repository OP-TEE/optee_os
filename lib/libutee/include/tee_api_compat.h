/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __TEE_API_COMPAT_H
#define __TEE_API_COMPAT_H

#if __OPTEE_CORE_API_COMPAT_1_1
/* Types */
#define TEE_ObjectInfo __GP11_TEE_ObjectInfo

/* Functions */
#define TEE_GetNextPersistentObject __GP11_TEE_GetNextPersistentObject
#define TEE_GetObjectInfo1 __GP11_TEE_GetObjectInfo1
#define TEE_GetObjectInfo __GP11_TEE_GetObjectInfo
#endif

#endif /*__TEE_API_COMPAT_H*/
