/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <tee/tee_cryp_provider.h>

#if !defined(_CFG_CRYPTO_WITH_HASH)
TEE_Result crypto_hash_get_ctx_size(uint32_t algo __unused,
				    size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_hash_init(void *ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
TEE_Result crypto_hash_update(void *ctx __unused, uint32_t algo __unused,
			      const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
TEE_Result crypto_hash_final(void *ctx __unused, uint32_t algo __unused,
			     uint8_t *digest __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*_CFG_CRYPTO_WITH_HASH*/
