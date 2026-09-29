// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Vaisala Oyj.
 */

#include <assert.h>
#include <pta_system.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>
#include <app_secrets_ta.h>
#include "user_ta_header_defines.h"

#define IV_SIZE			12
#define TAG_SIZE		16
#define MAX_BUF_SIZE		4096
#define AS_BLOB_VERSION		1
#define AS_MAGIC		0x41534543

static const char sealing_op_derivation_extra[] = "sealing";

struct secret_blob_hdr {
	uint32_t magic;
	uint32_t version;
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];
	uint8_t encrypted_payload[];
};

struct plaintext_payload {
	uint32_t client_login;
	TEE_UUID client_uuid;
	uint8_t data[];
};

#define SEALING_OVERHEAD (sizeof(struct secret_blob_hdr) + \
			  sizeof(struct plaintext_payload))

static_assert(MAX_BUF_SIZE >= SEALING_OVERHEAD,
	      "MAX_BUF_SIZE must be at least SEALING_OVERHEAD");

static TEE_Result derive_unique_key(void *key, size_t key_size,
				    const void *extra, size_t extra_size)
{
	static const TEE_UUID system_uuid = PTA_SYSTEM_UUID;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	if (extra && extra_size) {
		params[0].memref.buffer = (void *)extra;
		params[0].memref.size = extra_size;
	}

	params[1].memref.buffer = key;
	params[1].memref.size = key_size;

	res = TEE_OpenTASession(&system_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("Can't open session to system PTA");
		return res;
	}

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
				  param_types, params, &ret_orig);
	if (res != TEE_SUCCESS)
		EMSG("Can't invoke system PTA");

	TEE_CloseTASession(sess);

	return res;
}

static TEE_Result huk_ae_encrypt(TEE_OperationHandle crypto_op,
				 const uint8_t *in, size_t in_sz,
				 uint8_t *out, size_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct secret_blob_hdr *hdr = (struct secret_blob_hdr *)(void *)out;
	struct plaintext_payload *payload = NULL;
	size_t encrypted_payload_len = 0;
	size_t required_sz = 0;
	size_t tag_len = TAG_SIZE;
	TEE_Identity id = { 0 };
	uint8_t *payload_buf = NULL;
	size_t payload_buf_sz = 0;

	hdr->magic = AS_MAGIC;
	hdr->version = AS_BLOB_VERSION;

	res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,
					"gpd.client.identity", &id);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get client identity: 0x%08x", res);
		return res;
	}

	TEE_GenerateRandom(hdr->iv, IV_SIZE);

	res = TEE_AEInit(crypto_op, hdr->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
	if (res)
		return res;

	TEE_AEUpdateAAD(crypto_op, &hdr->magic, sizeof(hdr->magic));
	TEE_AEUpdateAAD(crypto_op, &hdr->version, sizeof(hdr->version));

	if (ADD_OVERFLOW(sizeof(struct plaintext_payload), in_sz,
			 &payload_buf_sz))
		return TEE_ERROR_SECURITY;
	payload_buf = TEE_Malloc(payload_buf_sz, TEE_MALLOC_FILL_ZERO);
	if (!payload_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	payload = (struct plaintext_payload *)(void *)payload_buf;
	payload->client_login = id.login;
	payload->client_uuid = id.uuid;
	memcpy(payload->data, in, in_sz);

	if (ADD_OVERFLOW(sizeof(*hdr), payload_buf_sz, &required_sz)) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	if (required_sz > *out_sz) {
		*out_sz = required_sz;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	encrypted_payload_len = payload_buf_sz;
	res = TEE_AEEncryptFinal(crypto_op, payload_buf, payload_buf_sz,
				 hdr->encrypted_payload, &encrypted_payload_len,
				 hdr->tag, &tag_len);
	if (res || tag_len != TAG_SIZE) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	if (ADD_OVERFLOW(encrypted_payload_len, sizeof(*hdr), out_sz))
		res = TEE_ERROR_SECURITY;

out:
	memzero_explicit(payload_buf, payload_buf_sz);
	TEE_Free(payload_buf);
	return res;
}

static TEE_Result huk_ae_decrypt(TEE_OperationHandle crypto_op,
				 const uint8_t *in, size_t in_sz,
				 uint8_t *out, size_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const struct secret_blob_hdr *hdr =
		(const struct secret_blob_hdr *)(const void *)in;
	size_t encrypted_payload_len = 0;

	if (hdr->magic != AS_MAGIC) {
		DMSG("Invalid blob magic 0x%08x", hdr->magic);
		return TEE_ERROR_SECURITY;
	}

	if (!hdr->version || hdr->version > AS_BLOB_VERSION) {
		DMSG("Unsupported blob version %u (max supported: %u)",
		     hdr->version, AS_BLOB_VERSION);
		return TEE_ERROR_SECURITY;
	}

	if (SUB_OVERFLOW(in_sz, sizeof(*hdr), &encrypted_payload_len))
		return TEE_ERROR_SECURITY;
	if (encrypted_payload_len > *out_sz) {
		*out_sz = encrypted_payload_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = TEE_AEInit(crypto_op, hdr->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
	if (res)
		return res;

	TEE_AEUpdateAAD(crypto_op, &hdr->magic, sizeof(hdr->magic));
	TEE_AEUpdateAAD(crypto_op, &hdr->version, sizeof(hdr->version));

	res = TEE_AEDecryptFinal(crypto_op, hdr->encrypted_payload,
				 encrypted_payload_len, out, out_sz,
				 (void *)hdr->tag, TAG_SIZE);
	if (res)
		res = TEE_ERROR_SECURITY;

	return res;
}

static TEE_Result huk_crypt(TEE_OperationMode mode, const uint8_t *in,
			    size_t in_sz, uint8_t *out, size_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle crypto_op = TEE_HANDLE_NULL;
	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	uint8_t huk_key[TA_DERIVED_KEY_MAX_SIZE] = { };
	TEE_Attribute attr = { };
	uint8_t *local_in = NULL;
	uint8_t *local_out = NULL;
	size_t local_out_sz = 0;

	local_in = TEE_Malloc(in_sz, TEE_MALLOC_FILL_ZERO);
	if (!local_in)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(local_in, in, in_sz);

	if (ADD_OVERFLOW(in_sz, SEALING_OVERHEAD, &local_out_sz)) {
		TEE_Free(local_in);
		return TEE_ERROR_SECURITY;
	}
	local_out = TEE_Malloc(local_out_sz, TEE_MALLOC_FILL_ZERO);
	if (!local_out) {
		TEE_Free(local_in);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = TEE_AllocateOperation(&crypto_op, TEE_ALG_AES_GCM, mode,
				    sizeof(huk_key) * 8);
	if (res)
		goto out_bufs;

	res = derive_unique_key(huk_key, sizeof(huk_key),
				sealing_op_derivation_extra,
				sizeof(sealing_op_derivation_extra) - 1);
	if (res) {
		EMSG("derive_unique_key failed: returned %#"PRIx32, res);
		goto out_op;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(huk_key) * 8,
					  &hkey);
	if (res)
		goto out_op;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, huk_key,
			     sizeof(huk_key));

	res = TEE_PopulateTransientObject(hkey, &attr, 1);
	if (res)
		goto out_key;

	res = TEE_SetOperationKey(crypto_op, hkey);
	if (res)
		goto out_key;

	if (mode == TEE_MODE_ENCRYPT) {
		res = huk_ae_encrypt(crypto_op, local_in, in_sz, local_out,
				     out_sz);
		if (res)
			DMSG("huk_AE_encrypt failed: returned %#"PRIx32, res);
	} else if (mode == TEE_MODE_DECRYPT) {
		res = huk_ae_decrypt(crypto_op, local_in, in_sz, local_out,
				     out_sz);
		if (res)
			DMSG("huk_AE_decrypt failed: returned %#"PRIx32, res);
	} else {
		TEE_Panic(0);
	}

	if (res == TEE_SUCCESS)
		memcpy(out, local_out, *out_sz);

out_key:
	TEE_FreeTransientObject(hkey);
out_op:
	TEE_FreeOperation(crypto_op);
	memzero_explicit(huk_key, sizeof(huk_key));
out_bufs:
	memzero_explicit(local_in, in_sz);
	TEE_Free(local_in);
	memzero_explicit(local_out, local_out_sz);
	TEE_Free(local_out);
	return res;
}

static TEE_Result seal_secret(uint32_t types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *in = NULL;
	size_t in_sz = 0;
	uint8_t *out = NULL;
	size_t out_sz = 0;
	size_t sealed_sz = 0;

	DMSG("Invoked TA_APPSECRETS_CMD_SEAL_SECRET");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	in = params[0].memref.buffer;
	in_sz = params[0].memref.size;
	out = params[1].memref.buffer;
	out_sz = params[1].memref.size;

	if (!in || !in_sz || in_sz > (MAX_BUF_SIZE - SEALING_OVERHEAD))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!out && out_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ADD_OVERFLOW(in_sz, SEALING_OVERHEAD, &sealed_sz) ||
	    sealed_sz > out_sz) {
		params[1].memref.size = sealed_sz;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = huk_crypt(TEE_MODE_ENCRYPT, in, in_sz, out, &out_sz);
	if (res == TEE_SUCCESS) {
		assert(out_sz == in_sz + SEALING_OVERHEAD);
		params[1].memref.size = out_sz;
	}

	return res;
}

static TEE_Result unseal_secret(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Identity id = { 0 };
	uint8_t *in = NULL;
	size_t in_sz = 0;
	uint8_t *out = NULL;
	size_t out_sz = 0;
	uint8_t *decrypted = NULL;
	size_t decrypted_sz = 0;
	size_t decrypted_alloc_sz = 0;
	struct plaintext_payload *payload = NULL;
	size_t user_data_sz = 0;
	size_t unsealed_sz = 0;

	DMSG("Invoked TA_APPSECRETS_CMD_UNSEAL_SECRET");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	in = params[0].memref.buffer;
	in_sz = params[0].memref.size;
	out = params[1].memref.buffer;
	out_sz = params[1].memref.size;

	if (!in || in_sz <= sizeof(struct secret_blob_hdr) ||
	    in_sz > MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!out && out_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_sz < SEALING_OVERHEAD)
		return TEE_ERROR_SECURITY;

	if (SUB_OVERFLOW(in_sz, SEALING_OVERHEAD, &unsealed_sz) ||
	    unsealed_sz > out_sz) {
		params[1].memref.size = unsealed_sz;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,
					"gpd.client.identity", &id);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get client identity: 0x%08x", res);
		return res;
	}

	if (SUB_OVERFLOW(in_sz, sizeof(struct secret_blob_hdr), &decrypted_sz))
		return TEE_ERROR_SECURITY;
	decrypted_alloc_sz = decrypted_sz;
	decrypted = TEE_Malloc(decrypted_alloc_sz, TEE_MALLOC_FILL_ZERO);
	if (!decrypted)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = huk_crypt(TEE_MODE_DECRYPT, in, in_sz, decrypted, &decrypted_sz);
	if (res != TEE_SUCCESS)
		goto out;

	assert(decrypted_sz == in_sz - sizeof(struct secret_blob_hdr));

	if (SUB_OVERFLOW(decrypted_sz, sizeof(struct plaintext_payload),
			 &user_data_sz)) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	payload = (struct plaintext_payload *)(void *)decrypted;
	if (payload->client_login != id.login ||
	    TEE_MemCompare(&payload->client_uuid, &id.uuid, sizeof(TEE_UUID))) {
		DMSG("Client identity mismatch");
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	if (user_data_sz > out_sz) {
		params[1].memref.size = user_data_sz;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (out && user_data_sz)
		memcpy(out, payload->data, user_data_sz);
	params[1].memref.size = user_data_sz;

out:
	memzero_explicit(decrypted, decrypted_alloc_sz);
	TEE_Free(decrypted);
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
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_APPSECRETS_CMD_SEAL_SECRET:
		return seal_secret(pt, params);
	case TA_APPSECRETS_CMD_UNSEAL_SECRET:
		return unseal_secret(pt, params);
	default:
		EMSG("Command ID %#"PRIx32" is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
