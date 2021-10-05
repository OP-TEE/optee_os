// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019-2020, Linaro Limited
 */

#include <assert.h>
#include <pta_system.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trusted_keys.h>
#include <util.h>

#define IV_SIZE			16
#define TAG_SIZE		16
#define MAX_BUF_SIZE		512

/*
 * Acronym:
 *
 * TK - Trusted Key
 */

struct tk_blob_hdr {
	uint8_t reserved;
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];
	uint8_t enc_key[];
};

static TEE_Result get_random(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *rng_buf = NULL;

	DMSG("Invoked TA_CMD_GET_RANDOM");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || !params[0].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	rng_buf = TEE_Malloc(params[0].memref.size, TEE_MALLOC_FILL_ZERO);
	if (!rng_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_GenerateRandom(rng_buf, params[0].memref.size);
	memcpy(params[0].memref.buffer, rng_buf, params[0].memref.size);
	memzero_explicit(rng_buf, params[0].memref.size);

	TEE_Free(rng_buf);

	return TEE_SUCCESS;
}

static TEE_Result derive_unique_key(uint8_t *key, uint16_t key_size,
				    uint8_t *extra, uint16_t extra_size)
{
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);

	res = TEE_OpenTASession(&(const TEE_UUID)PTA_SYSTEM_UUID,
				TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
				&ret_orig);
	if (res)
		return res;

	if (extra && extra_size) {
		params[0].memref.buffer = extra;
		params[0].memref.size = extra_size;
	}

	params[1].memref.buffer = key;
	params[1].memref.size = key_size;

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
				  param_types, params, &ret_orig);

	TEE_CloseTASession(sess);

	return res;
}

static TEE_Result huk_ae_encrypt(TEE_OperationHandle crypto_op, uint8_t *in,
				 uint32_t in_sz, uint8_t *out, uint32_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tk_blob_hdr *hdr = (struct tk_blob_hdr *)out;
	uint8_t iv[IV_SIZE] = { 0 };
	uint32_t enc_key_len = in_sz;
	uint32_t tag_len = TAG_SIZE;

	hdr->reserved = 0;
	TEE_GenerateRandom(iv, IV_SIZE);
	memcpy(hdr->iv, iv, IV_SIZE);

	res = TEE_AEInit(crypto_op, hdr->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
	if (res)
		return res;

	res = TEE_AEEncryptFinal(crypto_op, in, in_sz, hdr->enc_key,
				 &enc_key_len, hdr->tag, &tag_len);
	if (res || tag_len != TAG_SIZE)
		return TEE_ERROR_SECURITY;

	if (ADD_OVERFLOW(enc_key_len, sizeof(*hdr), out_sz))
		return TEE_ERROR_SECURITY;

	return res;
}

static TEE_Result huk_ae_decrypt(TEE_OperationHandle crypto_op, uint8_t *in,
				 uint32_t in_sz, uint8_t *out, uint32_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tk_blob_hdr *hdr = (struct tk_blob_hdr *)in;
	uint8_t tag[TAG_SIZE] = { 0 };
	uint32_t enc_key_len = 0;

	if (SUB_OVERFLOW(in_sz, sizeof(*hdr), &enc_key_len))
		return TEE_ERROR_SECURITY;

	res = TEE_AEInit(crypto_op, hdr->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
	if (res)
		return res;

	memcpy(tag, hdr->tag, TAG_SIZE);
	res = TEE_AEDecryptFinal(crypto_op, hdr->enc_key, enc_key_len, out,
				 out_sz, tag, TAG_SIZE);
	if (res)
		res = TEE_ERROR_SECURITY;

	return res;
}

static TEE_Result huk_crypt(TEE_OperationMode mode, uint8_t *in, uint32_t in_sz,
			    uint8_t *out, uint32_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle crypto_op = TEE_HANDLE_NULL;
	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	uint8_t huk_key[TA_DERIVED_KEY_MAX_SIZE] = { };
	TEE_Attribute attr = { };

	res = TEE_AllocateOperation(&crypto_op, TEE_ALG_AES_GCM, mode,
				    sizeof(huk_key) * 8);
	if (res)
		return res;

	res = derive_unique_key(huk_key, sizeof(huk_key), NULL, 0);
	if (res) {
		EMSG("derive_unique_key failed: returned %#"PRIx32, res);
		goto out_op;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(huk_key) * 8,
					  &hkey);
	if (res)
		goto out_op;

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = huk_key;
	attr.content.ref.length = sizeof(huk_key);

	res = TEE_PopulateTransientObject(hkey, &attr, 1);
	if (res)
		goto out_key;

	res = TEE_SetOperationKey(crypto_op, hkey);
	if (res)
		goto out_key;

	if (mode == TEE_MODE_ENCRYPT) {
		res = huk_ae_encrypt(crypto_op, in, in_sz, out, out_sz);
		if (res)
			EMSG("huk_AE_encrypt failed: returned %#"PRIx32, res);
	} else if (mode == TEE_MODE_DECRYPT) {
		res = huk_ae_decrypt(crypto_op, in, in_sz, out, out_sz);
		if (res)
			EMSG("huk_AE_decrypt failed: returned %#"PRIx32, res);
	} else {
		TEE_Panic(0);
	}

out_key:
	TEE_FreeTransientObject(hkey);
out_op:
	TEE_FreeOperation(crypto_op);
	memzero_explicit(huk_key, sizeof(huk_key));
	return res;
}

static TEE_Result seal_trusted_key(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *in = NULL;
	uint32_t in_sz = 0;
	uint8_t *out = NULL;
	uint32_t out_sz = 0;

	DMSG("Invoked TA_CMD_SEAL");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	in = params[0].memref.buffer;
	in_sz = params[0].memref.size;
	out = params[1].memref.buffer;
	out_sz = params[1].memref.size;

	if (!in || !in_sz || in_sz > MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((!out && out_sz) ||
	    (out && !IS_ALIGNED_WITH_TYPE(out, struct tk_blob_hdr)) ||
	    out_sz > MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((in_sz + sizeof(struct tk_blob_hdr)) > out_sz) {
		params[1].memref.size = in_sz + sizeof(struct tk_blob_hdr);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = huk_crypt(TEE_MODE_ENCRYPT, in, in_sz, out, &out_sz);
	if (res == TEE_SUCCESS) {
		assert(out_sz == in_sz + sizeof(struct tk_blob_hdr));
		params[1].memref.size = out_sz;
	}

	return res;
}

static TEE_Result unseal_trusted_key(uint32_t types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *in = NULL;
	uint32_t in_sz = 0;
	uint8_t *out = NULL;
	uint32_t out_sz = 0;

	DMSG("Invoked TA_CMD_UNSEAL");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	in = params[0].memref.buffer;
	in_sz = params[0].memref.size;
	out = params[1].memref.buffer;
	out_sz = params[1].memref.size;

	if (!in || !IS_ALIGNED_WITH_TYPE(in, struct tk_blob_hdr) ||
	    in_sz <= sizeof(struct tk_blob_hdr) || in_sz > MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((!out && out_sz) || out_sz > MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_sz > (out_sz + sizeof(struct tk_blob_hdr))) {
		params[1].memref.size = in_sz - sizeof(struct tk_blob_hdr);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = huk_crypt(TEE_MODE_DECRYPT, in, in_sz, out, &out_sz);
	if (res == TEE_SUCCESS) {
		assert(out_sz == in_sz - sizeof(struct tk_blob_hdr));
		params[1].memref.size = out_sz;
	}

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **session __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_PropSetHandle h = TEE_HANDLE_NULL;
	TEE_Identity id = { };

	res = TEE_AllocatePropertyEnumerator(&h);
	if (res)
		goto out;

	TEE_StartPropertyEnumerator(h, TEE_PROPSET_CURRENT_CLIENT);

	res = TEE_GetPropertyAsIdentity(h, NULL, &id);
	if (res)
		goto out;

	if (id.login != TEE_LOGIN_REE_KERNEL)
		res = TEE_ERROR_ACCESS_DENIED;

out:
	if (h)
		TEE_FreePropertyEnumerator(h);
	return res;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_CMD_GET_RANDOM:
		return get_random(pt, params);
	case TA_CMD_SEAL:
		return seal_trusted_key(pt, params);
	case TA_CMD_UNSEAL:
		return unseal_trusted_key(pt, params);
	default:
		EMSG("Command ID %#"PRIx32" is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
