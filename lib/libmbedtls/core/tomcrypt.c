// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <tomcrypt_init.h>

TEE_Result crypto_init(void)
{
	tomcrypt_init();

	return TEE_SUCCESS;
}
