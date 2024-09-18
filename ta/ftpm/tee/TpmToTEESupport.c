/* SPDX-License-Identifier: BSD-2-Clause */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 */

#include "Tpm.h"

#if defined(HASH_LIB_TEE) || defined(MATH_LIB_TEE) || defined(SYM_LIB_TEE)

LIB_EXPORT int SupportLibInit(void)
{
    return TRUE;
}

#endif
