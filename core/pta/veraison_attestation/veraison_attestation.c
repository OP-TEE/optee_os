// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <base64.h>
#include <config.h>
#include <crypto/crypto.h>
#include <drivers/caam_extension.h>
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
#define INSTANCE_ID_LEN 33

#define PUBKEY_COORD_SIZE 32
#define KEY_PARAM_HEADER_SIZE (2 * PUBKEY_COORD_SIZE)
/* The private key is at least the plain P-256 scalar */
#define KEY_PARAM_MIN_SIZE (KEY_PARAM_HEADER_SIZE + PUBKEY_COORD_SIZE)

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
	const uint8_t *private_key = NULL;
	size_t private_key_len = 0;
	const uint8_t *public_key_x = NULL;
	const uint8_t *public_key_y = NULL;
	uint8_t test_public_key_x[PUBKEY_COORD_SIZE] = { 0 };
	uint8_t test_public_key_y[PUBKEY_COORD_SIZE] = { 0 };
	TEE_Result status = TEE_SUCCESS;

	const char eat_profile[] = EAT_PROFILE;
	const int psa_client_id = CLIENT_ID;
	int psa_security_lifecycle = LIFECYCLE;
	const char measurement_type[] = MEASURMENT_TYPE;
	uint8_t signer_id[SIGNER_ID_LEN] = { 0 };
	uint8_t psa_instance_id[INSTANCE_ID_LEN] = { 0 };

	uint8_t measurement_value[TEE_SHA256_HASH_SIZE] = { 0 };
	size_t b64_measurement_value_len = TEE_SHA256_HASH_SIZE * 2;
	char b64_measurement_value[TEE_SHA256_HASH_SIZE * 2] = { 0 };

	UsefulBufC ubc_cbor_evidence = { NULL, 0 };
	UsefulBufC ubc_cose_evidence = { NULL, 0 };

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE) &&
	    param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!nonce || !nonce_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!output_buffer && *output_buffer_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	/*
	 * The signing key, when the caller supplies one: the public key
	 * coordinates followed by the private key, a plain P-256 scalar or a
	 * serialized CAAM black key. The embedded test key otherwise.
	 */
	if (TEE_PARAM_TYPE_GET(param_types, 3) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		const uint8_t *p = params[3].memref.buffer;
		size_t len = params[3].memref.size;

		if (!p || len < KEY_PARAM_MIN_SIZE ||
		    len > KEY_PARAM_HEADER_SIZE + MAX_KEY_SIZE)
			return TEE_ERROR_BAD_PARAMETERS;
		public_key_x = p;
		public_key_y = p + PUBKEY_COORD_SIZE;
		private_key = p + KEY_PARAM_HEADER_SIZE;
		private_key_len = len - KEY_PARAM_HEADER_SIZE;
	} else {
		get_test_key_pubkey(test_public_key_x, test_public_key_y);
		public_key_x = test_public_key_x;
		public_key_y = test_public_key_y;
	}

	/* The instance-id names the key in use */
	status = compute_instance_id(public_key_x, public_key_y,
				     psa_instance_id);
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

	status = get_ta_signer_id(&s->ctx->uuid, signer_id);
	if (status != TEE_SUCCESS)
		return status;

	if (IS_ENABLED(CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS)) {
		status = platform_get_lifecycle(&psa_security_lifecycle);
		if (status != TEE_SUCCESS)
			return status;
	}

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
	ubc_cose_evidence = generate_cose_evidence(ubc_cbor_evidence,
						   private_key, private_key_len,
						   public_key_x, public_key_y);
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

#ifdef CFG_NXP_CAAM_ECC_DRV
#define KEY_SIZE_BIT (PUBKEY_COORD_SIZE * 8)

/* Export a coordinate as a big-endian number of PUBKEY_COORD_SIZE bytes */
static TEE_Result export_coord(struct bignum *bn, uint8_t *out)
{
	size_t len = crypto_bignum_num_bytes(bn);

	if (len > PUBKEY_COORD_SIZE)
		return TEE_ERROR_GENERIC;
	memset(out, 0, PUBKEY_COORD_SIZE);
	crypto_bignum_bn2bin(bn, out + PUBKEY_COORD_SIZE - len);

	return TEE_SUCCESS;
}

static TEE_Result cmd_generate_keypair(uint32_t param_types,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	struct ecc_keypair key = { };
	size_t key_len = 0;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[1].memref.buffer || !params[2].memref.buffer ||
	    params[1].memref.size < PUBKEY_COORD_SIZE ||
	    params[2].memref.size < PUBKEY_COORD_SIZE) {
		params[1].memref.size = PUBKEY_COORD_SIZE;
		params[2].memref.size = PUBKEY_COORD_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = crypto_acipher_alloc_ecc_keypair(&key, TEE_TYPE_ECDSA_KEYPAIR,
					       KEY_SIZE_BIT);
	if (res != TEE_SUCCESS)
		return res;
	key.curve = TEE_ECC_CURVE_NIST_P256;

	/* The CAAM ECC driver generates a black key: key.d is its blob */
	res = crypto_acipher_gen_ecc_key(&key, KEY_SIZE_BIT);
	if (res != TEE_SUCCESS)
		goto out;

	key_len = crypto_bignum_num_bytes(key.d);
	if (!params[0].memref.buffer || params[0].memref.size < key_len) {
		params[0].memref.size = key_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	crypto_bignum_bn2bin(key.d, params[0].memref.buffer);
	params[0].memref.size = key_len;

	res = export_coord(key.x, params[1].memref.buffer);
	if (res != TEE_SUCCESS)
		goto out;
	params[1].memref.size = PUBKEY_COORD_SIZE;
	res = export_coord(key.y, params[2].memref.buffer);
	if (res != TEE_SUCCESS)
		goto out;
	params[2].memref.size = PUBKEY_COORD_SIZE;
out:
	crypto_bignum_free(&key.d);
	crypto_bignum_free(&key.x);
	crypto_bignum_free(&key.y);

	return res;
}

static TEE_Result cmd_convert_to_blackkey(uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	size_t out_size = params[1].memref.size;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer ||
	    params[0].memref.size != PUBKEY_COORD_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = caam_key_wrap_black(params[0].memref.buffer, PUBKEY_COORD_SIZE,
				  params[1].memref.buffer, &out_size);
	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER)
		params[1].memref.size = out_size;

	return res;
}
#endif /* CFG_NXP_CAAM_ECC_DRV */

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE:
		return cmd_get_cbor_evidence(param_types, params);
#ifdef CFG_NXP_CAAM_ECC_DRV
	case PTA_VERAISON_ATTESTATION_GENERATE_KEYPAIR:
		return cmd_generate_keypair(param_types, params);
	case PTA_VERAISON_ATTESTATION_CONVERT_TO_BLACKKEY:
		return cmd_convert_to_blackkey(param_types, params);
#else
	case PTA_VERAISON_ATTESTATION_GENERATE_KEYPAIR:
	case PTA_VERAISON_ATTESTATION_CONVERT_TO_BLACKKEY:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_VERAISON_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
