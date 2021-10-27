// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_store.h>
#include <mm/file.h>
#include <pta_attestation.h>
#include <stdlib.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/uuid.h>
#include <utee_defines.h>

#define PTA_NAME "attestation.pta"

/* Signing key is defined in signing_key.c */
extern uint32_t pta_attestation_key_exponent;
extern uint8_t pta_attestation_key_modulus[];
extern size_t pta_attestation_key_modulus_size;
extern uint8_t pta_attestation_key_private_exponent[];
extern size_t pta_attestation_key_private_exponent_size;

static TEE_Result hash_binary(const TEE_UUID *uuid, uint8_t *hash)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	unsigned int tag_len = FILE_TAG_SIZE;
	const struct ts_store_ops *ops = NULL;
	struct ts_store_handle *h = NULL;

	SCATTERED_ARRAY_FOREACH(ops, ta_stores, struct ts_store_ops) {
		res = ops->open(uuid, &h);
		if (!res)
			break;  /* TA found */
	}
	if (res)
		return res;

	/*
	 * Output hash size is assumed to be the same size as the file tag
	 * size which is the size of the digest in the TA shdr. If one or the
	 * other changes, additional hashing will be needed.
	 */
	COMPILE_TIME_ASSERT(FILE_TAG_SIZE == TEE_SHA256_HASH_SIZE);
	assert(ops);
	res = ops->get_tag(h, hash, &tag_len);
	if (res)
		goto out;

	DMSG("TA %pUl hash:", uuid);
	DHEXDUMP(hash, TEE_SHA256_HASH_SIZE);
out:
	ops->close(h);
	return res;
}

static TEE_Result digest_nonce_and_hash(uint8_t *digest, uint8_t *nonce,
					size_t nonce_sz, uint8_t *hash)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	if (nonce) {
		res = crypto_hash_update(ctx, nonce, nonce_sz);
		if (res)
			goto out;
	}
	res = crypto_hash_update(ctx, hash, TEE_SHA256_HASH_SIZE);
	if (res)
		goto out;
	res = crypto_hash_final(ctx, digest, TEE_SHA256_HASH_SIZE);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result sign_digest(uint8_t *sig, size_t sig_len,
			      const uint8_t *digest)
{
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(pta_attestation_key_exponent);
	size_t key_size_bits = 8 * pta_attestation_key_modulus_size;
	size_t salt_len = TEE_SHA256_HASH_SIZE;
	TEE_Result res = TEE_SUCCESS;
	struct rsa_keypair kp = { };

	res = crypto_acipher_alloc_rsa_keypair(&kp, key_size_bits);
	if (res)
		return res;
	res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), kp.e);
	if (res)
		goto out;
	res = crypto_bignum_bin2bn(pta_attestation_key_modulus,
				   pta_attestation_key_modulus_size, kp.n);
	if (res)
		goto out;
	res = crypto_bignum_bin2bn(pta_attestation_key_private_exponent,
				   pta_attestation_key_private_exponent_size,
				   kp.d);
	if (res)
		goto out;
	res = crypto_acipher_rsassa_sign(TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
					 &kp, salt_len, digest,
					 TEE_SHA256_HASH_SIZE, sig, &sig_len);
out:
	crypto_acipher_free_rsa_keypair(&kp);
	return res;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { };
	TEE_UUID *uuid = params[0].memref.buffer;
	size_t uuid_sz = params[0].memref.size;
	uint8_t *nonce = params[1].memref.buffer;
	size_t nonce_sz = params[1].memref.size;
	uint8_t *out = params[2].memref.buffer;
	size_t out_sz = params[2].memref.size;
	size_t min_out_sz = TEE_SHA256_HASH_SIZE +
			    pta_attestation_key_modulus_size;
	TEE_Result res = TEE_SUCCESS;

	if (cmd_id != PTA_ATTESTATION_HASH_TA)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (uuid_sz != sizeof(*uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!out && out_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	if (out_sz < min_out_sz) {
		params[2].memref.size = min_out_sz;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/*
	 * out = [ hash | sig(sha256(nonce | hash)) ]
	 *         ^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^
	 *          32B                modulus size
	 */

	res = hash_binary(uuid, out);
	if (res)
		return res;
	res = digest_nonce_and_hash(digest, nonce, nonce_sz, out);
	if (res)
		return res;
	return sign_digest(out + TEE_SHA256_HASH_SIZE,
			   out_sz - TEE_SHA256_HASH_SIZE, digest);
}

pseudo_ta_register(.uuid = PTA_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
