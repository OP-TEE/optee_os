/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEE_ACIPHER_H
#define TEE_ACIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <tee_api_types.h>


TEE_Result tee_acipher_gen_rsa_keys(rsa_key *ltc_key, size_t key_size);

TEE_Result tee_acipher_gen_dh_keys(dh_key *ltc_key, void *q, size_t xbits);

TEE_Result tee_acipher_gen_dsa_keys(dsa_key *ltc_key, size_t key_size);

/*
 * Public_key is an input big number
 * Secret is an output big number
 */
TEE_Result tee_derive_dh_shared_secret(
		dh_key *private_key, void *public_key, void *secret);

TEE_Result tee_acipher_rsadorep(
	rsa_key *ltc_key,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len);

TEE_Result tee_acipher_rsaes_decrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len);

TEE_Result tee_acipher_rsaes_encrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len);

/* passing salt_len == -1 -> use default value */
TEE_Result tee_acipher_rsassa_sign(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);

/* passing salt_len == -1 -> use default value */
TEE_Result tee_acipher_rsassa_verify(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

TEE_Result tee_acipher_dsa_sign(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);

TEE_Result tee_acipher_dsa_verify(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

#endif /* TEE_ACIPHER_H */
