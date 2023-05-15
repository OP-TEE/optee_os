// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <compiler.h>
#include <config.h>
#include <crypto/crypto.h>
#include <fsl_sss_user_apis.h>
#include <glue.h>
#include <stdlib.h>

sss_status_t glue_mac_context_init(void **mac, const uint8_t *key, size_t len)
{
	if (crypto_mac_alloc_ctx(mac, TEE_ALG_AES_CMAC))
		return kStatus_SSS_Fail;

	if (crypto_mac_init(*mac, key, len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

void glue_mac_context_free(void *mac)
{
	crypto_mac_free_ctx(mac);
}

sss_status_t glue_mac_update(void *mac, const uint8_t *msg, size_t len)
{
	if (crypto_mac_update(mac, msg, len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t glue_mac_final(void *mac, uint8_t *buf, size_t len)
{
	if (crypto_mac_final(mac, buf, len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t glue_mac_one_go(void *mac, const uint8_t *msg, size_t msg_len,
			     uint8_t *buf, size_t mac_len)
{
	if (crypto_mac_update(mac, msg, msg_len))
		return kStatus_SSS_Fail;

	if (crypto_mac_final(mac, buf, mac_len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t glue_symmetric_context_init(void **cipher)
{
	if (crypto_cipher_alloc_ctx(cipher, TEE_ALG_AES_CBC_NOPAD))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t glue_cipher_one_go(void *cipher, TEE_OperationMode mode,
				uint8_t *iv, size_t iv_len,
				uint8_t *key, size_t key_len,
				const uint8_t *src, uint8_t *dst, size_t len)
{
	if (crypto_cipher_init(cipher, mode, key, key_len, NULL, 0, iv, iv_len))
		return kStatus_SSS_Fail;

	if (crypto_cipher_update(cipher, 0, true, src, len, dst))
		return kStatus_SSS_Fail;

	crypto_cipher_final(cipher);

	return kStatus_SSS_Success;
}

void glue_context_free(void *cipher)
{
	crypto_cipher_free_ctx(cipher);
}

sss_status_t glue_rng_get_random(uint8_t *data, size_t len)
{
	if (IS_ENABLED(CFG_NXP_SE05X_RNG_DRV))
		return kStatus_SSS_InvalidArgument;

	if (crypto_rng_read(data, len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}
