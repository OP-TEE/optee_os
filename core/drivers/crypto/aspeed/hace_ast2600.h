/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Aspeed Technology Inc.
 */
#ifndef __HACE_AST2600_H__
#define __HACE_AST2600_H__

#include <tee_api_types.h>

#ifdef CFG_CRYPTO_DRV_HASH
TEE_Result ast2600_drvcrypt_register_hash(void);
#else
static inline TEE_Result ast2600_drvcrypt_register_hash(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif
#endif
