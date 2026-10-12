// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <base64.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/early_ta.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_manager.h>
#include <kernel/user_ta.h>
#include <mempool.h>
#include <pta_veraison_attestation.h>
#include <stdlib.h>
#include <string.h>
#include <ta_pub_key.h>
#include <utee_defines.h>

#include "cbor.h"
#include "hash.h"
#include "key.h"
#include "platform.h"
#include "sign.h"

#define PTA_NAME "veraison_attestation.pta"

#define MAX_KEY_SIZE 4096
#define MAX_NONCE_SIZE 64
#define TEE_SHA256_HASH_SIZE 32

#define EAT_PROFILE "http://arm.com/psa/2.0.0"
#define CLIENT_ID 1
#define LIFECYCLE 12288
#define MEASURMENT_TYPE "PRoT"

/* Signer of the boot images when the platform does not say */
static const uint8_t test_boot_signer_id[SIGNER_ID_LEN] = {
	0xac, 0xbb, 0x11, 0xc7, 0xe4, 0xda, 0x21, 0x72,
	0x05, 0x52, 0x3c, 0xe4, 0xce, 0x1a, 0x24, 0x5a,
	0xe1, 0xa2, 0x39, 0xae, 0x3c, 0x6b, 0xfd, 0x9e,
	0x78, 0x71, 0xf7, 0xe5, 0xd8, 0xba, 0xe8, 0x6b,
};

static bool is_early_ta(const TEE_UUID *uuid)
{
	const struct embedded_ts *ta = NULL;

	if (IS_ENABLED(CFG_EARLY_TA))
		for_each_early_ta(ta)
			if (!memcmp(&ta->uuid, uuid, sizeof(*uuid)))
				return true;

	return false;
}

/* The hash of the key that signs the boot images, the core among them */
static TEE_Result get_boot_signer_id(uint8_t signer_id[SIGNER_ID_LEN])
{
	if (IS_ENABLED(CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS))
		return platform_get_boot_signer_id(signer_id);

	memcpy(signer_id, test_boot_signer_id, SIGNER_ID_LEN);

	return TEE_SUCCESS;
}

/*
 * The SHA-256 of the TA root public key the core verifies TAs against,
 * over the big-endian modulus followed by the big-endian 32-bit exponent
 */
static TEE_Result get_ta_root_key_id(uint8_t signer_id[SIGNER_ID_LEN])
{
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res != TEE_SUCCESS)
		return res;
	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, ta_pub_key_modulus,
				 ta_pub_key_modulus_size);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, (uint8_t *)&e, sizeof(e));
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_final(ctx, signer_id, SIGNER_ID_LEN);
out:
	crypto_hash_free_ctx(ctx);

	return res;
}

/*
 * Who vouches for the calling TA: a TA loaded from the REE file system or
 * the secure storage is verified against the TA root public key built into
 * the core, so that key is its signer. An early TA is part of the core
 * image and carries no signature of its own, so its signer is whoever
 * signed the core.
 */
static TEE_Result get_ta_signer_id(const TEE_UUID *uuid,
				   uint8_t signer_id[SIGNER_ID_LEN])
{
	if (is_early_ta(uuid))
		return get_boot_signer_id(signer_id);

	return get_ta_root_key_id(signer_id);
}

static TEE_Result cmd_get_cbor_evidence(uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint8_t *nonce = params[0].memref.buffer;
	const size_t nonce_sz = params[0].memref.size;
	uint8_t *output_buffer = params[1].memref.buffer;
	size_t *output_buffer_len = &params[1].memref.size;
	const uint8_t *psa_implementation_id = params[2].memref.buffer;
	const size_t psa_implementation_id_len = params[2].memref.size;
	struct ts_session *s = ts_get_calling_session();
	TEE_Result status = TEE_SUCCESS;

	const char eat_profile[] = EAT_PROFILE;
	const int psa_client_id = CLIENT_ID;
	int psa_security_lifecycle = LIFECYCLE;
	const char measurement_type[] = MEASURMENT_TYPE;
	uint8_t signer_id[SIGNER_ID_LEN] = { };
	uint8_t psa_instance_id[INSTANCE_ID_LEN] = { };
	const struct signing_key *skey = NULL;

	uint8_t measurement_value[TEE_SHA256_HASH_SIZE] = { 0 };
	size_t b64_measurement_value_len = TEE_SHA256_HASH_SIZE * 2;
	char b64_measurement_value[TEE_SHA256_HASH_SIZE * 2] = { 0 };

	UsefulBufC ubc_cbor_evidence = { NULL, 0 };
	UsefulBufC ubc_cose_evidence = { NULL, 0 };

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!nonce || !nonce_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!output_buffer && *output_buffer_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	status = key_get(&skey);
	if (status != TEE_SUCCESS)
		return status;

	status = compute_instance_id(skey, psa_instance_id);
	if (status != TEE_SUCCESS)
		return status;

	if (IS_ENABLED(CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS)) {
		status = platform_get_lifecycle(&psa_security_lifecycle);
		if (status != TEE_SUCCESS)
			return status;
	}

	status = get_ta_signer_id(&s->ctx->uuid, signer_id);
	if (status != TEE_SUCCESS)
		return status;

	/* Calculate measurement hash of memory */
	status = get_hash_ta_memory(measurement_value);
	if (status != TEE_SUCCESS)
		return status;

	/* Encode measurement_value to base64 */
	if (!base64_enc(measurement_value, TEE_SHA256_HASH_SIZE,
			b64_measurement_value,
			&b64_measurement_value_len)) {
		DMSG("Failed to encode measurement_value to base64");
		return TEE_ERROR_GENERIC;
	}
	DMSG("b64_measurement_value: %s", b64_measurement_value);

	/* Encode evidence to CBOR */
	ubc_cbor_evidence = generate_cbor_evidence(eat_profile,
						   psa_client_id,
						   psa_security_lifecycle,
						   psa_implementation_id,
						   psa_implementation_id_len,
						   measurement_type,
						   signer_id,
						   SIGNER_ID_LEN,
						   psa_instance_id,
						   INSTANCE_ID_LEN,
						   nonce,
						   nonce_sz,
						   measurement_value,
						   TEE_SHA256_HASH_SIZE);
	if (UsefulBuf_IsNULLC(ubc_cbor_evidence)) {
		DMSG("Failed to encode evidence to CBOR");
		return TEE_ERROR_GENERIC;
	}

	/* Sign the CBOR and generate a COSE evidence */
	ubc_cose_evidence = generate_cose_evidence(ubc_cbor_evidence, skey);
	if (UsefulBuf_IsNULLC(ubc_cose_evidence)) {
		DMSG("Failed to encode CBOR to COSE");
		status = TEE_ERROR_GENERIC;
		goto free_ubc_cbor_evidence;
	}

	/* Copy COSE evidence for return buffer */
	if (ubc_cose_evidence.len > *output_buffer_len) {
		*output_buffer_len = ubc_cose_evidence.len;
		status = TEE_ERROR_SHORT_BUFFER;
		goto free_ubc_cose_evidence;
	}
	memcpy(output_buffer, ubc_cose_evidence.ptr, ubc_cose_evidence.len);
	*output_buffer_len = ubc_cose_evidence.len;

	/* Free mempool allocation before returning to the caller */
free_ubc_cose_evidence:
	mempool_free(mempool_default, (void *)ubc_cose_evidence.ptr);
free_ubc_cbor_evidence:
	mempool_free(mempool_default, (void *)ubc_cbor_evidence.ptr);

	return status;
}

static TEE_Result cmd_get_public_key(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Param *px = &params[0];
	TEE_Param *py = &params[1];
	const struct signing_key *skey = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the parameters before the key is possibly generated */
	if (px->memref.size < SIGNING_KEY_COORD_SIZE ||
	    py->memref.size < SIGNING_KEY_COORD_SIZE) {
		px->memref.size = SIGNING_KEY_COORD_SIZE;
		py->memref.size = SIGNING_KEY_COORD_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}
	if (!px->memref.buffer || !py->memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	res = key_get(&skey);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(px->memref.buffer, skey->pub_x, SIGNING_KEY_COORD_SIZE);
	px->memref.size = SIGNING_KEY_COORD_SIZE;
	memcpy(py->memref.buffer, skey->pub_y, SIGNING_KEY_COORD_SIZE);
	py->memref.size = SIGNING_KEY_COORD_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result cmd_import_key(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const struct signing_key *skey = NULL;
	size_t n = 0;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	for (n = 0; n < 3; n++)
		if (!params[n].memref.buffer ||
		    params[n].memref.size != SIGNING_KEY_COORD_SIZE)
			return TEE_ERROR_BAD_PARAMETERS;

	return key_import(params[0].memref.buffer, params[1].memref.buffer,
			  params[2].memref.buffer, &skey);
}

/*
 * Only user TAs may use the PTA: the evidence is about the calling TA, and
 * the key the PTA signs with is the key of every TA's evidence.
 */
static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = ts_get_calling_session();

	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE:
		return cmd_get_cbor_evidence(param_types, params);
	case PTA_VERAISON_ATTESTATION_GET_PUBLIC_KEY:
		return cmd_get_public_key(param_types, params);
	case PTA_VERAISON_ATTESTATION_IMPORT_KEY:
		return cmd_import_key(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_VERAISON_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
