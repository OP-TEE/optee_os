// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <compiler.h>
#include <kernel/pseudo_ta.h>
#include <mempool.h>

#include "cbor.h"
#include "sign.h"

struct cbor_evidence_args {
	UsefulBufC ubc_eat_profile;
	int psa_client_id;
	int psa_security_lifecycle;
	UsefulBufC ubc_psa_implementation_id;
	UsefulBufC ubc_measurement_type;
	UsefulBufC ubc_signer_id;
	UsefulBufC ubc_psa_instance_id;
	UsefulBufC ubc_psa_nonce;
	UsefulBufC ubc_measurement_value;
};

struct cose_evidence_args {
	UsefulBufC ubc_cbor_evidence;
};

struct tbs_structure_args {
	UsefulBufC protected_header;
	UsefulBufC aad;
	UsefulBufC payload;
};

static void
encode_cbor_evidence(QCBOREncodeContext *context, UsefulBufC ubc_eat_profile,
		     const int psa_client_id, const int psa_security_lifecycle,
		     UsefulBufC ubc_psa_implementation_id,
		     UsefulBufC ubc_measurement_type, UsefulBufC ubc_signer_id,
		     UsefulBufC ubc_psa_instance_id, UsefulBufC ubc_psa_nonce,
		     UsefulBufC ubc_measurement_value)
{
	QCBOREncode_OpenMap(context);

	/* Profile Definition */
	QCBOREncode_AddTextToMapN(context, PSA_PROFILE_DEFINITION,
				  ubc_eat_profile);

	/* Client ID */
	QCBOREncode_AddInt64ToMapN(context, PSA_CLIENT_ID, psa_client_id);

	/* Security Lifecycle */
	QCBOREncode_AddInt64ToMapN(context, PSA_SECURITY_LIFECYCLE,
				   psa_security_lifecycle);

	/* Implementation ID */
	QCBOREncode_AddBytesToMapN(context, PSA_IMPLEMENTATION_ID,
				   ubc_psa_implementation_id);

	/* Software Components */
	QCBOREncode_OpenArrayInMapN(context, PSA_SW_COMPONENTS); /* [ */
	QCBOREncode_OpenMap(context); /* { */
	QCBOREncode_AddTextToMapN(context, PSA_SW_COMPONENT_MEASUREMENT_TYPE,
				  ubc_measurement_type);
	QCBOREncode_AddBytesToMapN(context, PSA_SW_COMPONENT_MEASUREMENT_VALUE,
				   ubc_measurement_value);
	QCBOREncode_AddBytesToMapN(context, PSA_SW_COMPONENT_SIGNER_ID,
				   ubc_signer_id);
	QCBOREncode_CloseMap(context); /* } */
	QCBOREncode_CloseArray(context); /* ] */

	/* Nonce */
	QCBOREncode_AddBytesToMapN(context, PSA_NONCE, ubc_psa_nonce);

	/* Instance ID */
	QCBOREncode_AddBytesToMapN(context, PSA_INSTANCE_ID,
				   ubc_psa_instance_id);

	QCBOREncode_CloseMap(context);
}

/* Generic function for encoding and buffer allocation */
static UsefulBufC build_encoded_buffer(void (*encode_func)(QCBOREncodeContext *,
							   void *),
				       void *encode_args)
{
	QCBOREncodeContext context = { };
	uint8_t *buffer = NULL;
	size_t required_size = 0;
	UsefulBufC encoded_data = { NULL, 0 };

	/* First encode: calculate the required length */
	QCBOREncode_Init(&context, (UsefulBuf){ NULL, INT32_MAX });
	encode_func(&context, encode_args);
	if (QCBOREncode_FinishGetSize(&context, &required_size) !=
	    QCBOR_SUCCESS) {
		return NULLUsefulBufC;
	}

	/* Allocate buffer for encoded data */
	buffer = mempool_alloc(mempool_default, required_size);
	if (!buffer) {
		DMSG("Failed to allocate buffer");
		return NULLUsefulBufC;
	}

	/* Second encode: encode data */
	QCBOREncode_Init(&context, (UsefulBuf){ buffer, required_size });
	encode_func(&context, encode_args);
	if (QCBOREncode_Finish(&context, &encoded_data) != QCBOR_SUCCESS) {
		mempool_free(mempool_default, buffer);
		return NULLUsefulBufC;
	}

	/* Verify the length of the encoded data */
	if (encoded_data.len != required_size) {
		DMSG("Unexpected length of encoded data");
		mempool_free(mempool_default, buffer);
		return NULLUsefulBufC;
	}

	return encoded_data;
}

static void encode_protected_header(QCBOREncodeContext *context)
{
	QCBOREncode_OpenMap(context);
	QCBOREncode_AddInt64ToMapN(context, COSE_HEADER_PARAM_ALG,
				   COSE_ALGORITHM_ES256);
	QCBOREncode_CloseMap(context);
}

static void encode_protected_header_wrapper(QCBOREncodeContext *context,
					    void *args __unused)
{
	encode_protected_header(context);
}

/*
 * Format of to-be-signed bytes. This is defined in COSE (RFC 8152)
 * section 4.4. It is the input to the hash.
 *
 * Sig_structure = [
 *    context : "Signature1",
 *    body_protected : empty_or_serialized_map,
 *    external_aad : bstr,
 *    payload : bstr
 * ]
 *
 * body_protected refers to the protected parameters from the main
 * COSE_Sign1 structure.
 */
static void encode_tbs_structure(QCBOREncodeContext *context,
				 UsefulBufC protected_header, UsefulBufC aad,
				 UsefulBufC payload)
{
	QCBOREncode_OpenArray(context);
	QCBOREncode_AddSZString(context, COSE_SIG_CONTEXT_STRING_SIGNATURE1);
	QCBOREncode_AddBytes(context, protected_header);
	QCBOREncode_AddBytes(context, aad);
	QCBOREncode_AddBytes(context, payload);
	QCBOREncode_CloseArray(context);
}

static void encode_tbs_structure_wrapper(QCBOREncodeContext *context,
					 void *args)
{
	struct tbs_structure_args *tbs_args =
		(struct tbs_structure_args *)args;

	encode_tbs_structure(context, tbs_args->protected_header, tbs_args->aad,
			     tbs_args->payload);
}

static UsefulBufC build_protected_header(void)
{
	return build_encoded_buffer(encode_protected_header_wrapper, NULL);
}

static UsefulBufC build_tbs_structure(UsefulBufC protected_header,
				      UsefulBufC aad, UsefulBufC payload)
{
	struct tbs_structure_args args = {
		.protected_header = protected_header,
		.aad = aad,
		.payload = payload,
	};

	return build_encoded_buffer(encode_tbs_structure_wrapper, &args);
}

static void encode_cose_evidence(QCBOREncodeContext *context,
				 UsefulBufC ubc_cbor_evidence)
{
	UsefulBufC protected_header = { NULL, 0 };
	UsefulBufC tbs_payload = { NULL, 0 };
	uint8_t signature[64] = { };
	size_t signature_len = 64;
	UsefulBufC signature_payload = { signature, signature_len };

	/* Add top level array for COSE_Sign1 */
	QCBOREncode_AddTag(context, CBOR_TAG_COSE_SIGN1);
	QCBOREncode_OpenArray(context);

	/* Encode protected header */
	protected_header = build_protected_header();
	if (UsefulBuf_IsNULLC(protected_header)) {
		DMSG("Failed to encode protected header payload");
		return;
	}

	/* Add protected header */
	QCBOREncode_AddBytes(context, protected_header);

	/* Add unprotected header (empty map) */
	QCBOREncode_OpenMap(context);
	QCBOREncode_CloseMap(context);

	/* Add the payload (evidence CBOR) */
	QCBOREncode_AddBytes(context, ubc_cbor_evidence);

	/* Encode "To Be Signed" payload */
	tbs_payload = build_tbs_structure(protected_header, NULLUsefulBufC,
					  ubc_cbor_evidence);
	if (UsefulBuf_IsNULLC(tbs_payload)) {
		DMSG("Failed to encode to-be-signed payload");
		mempool_free(mempool_default, (void *)protected_header.ptr);
		return;
	}

	/* Calculate a signature and add the signature to payload */
	if (sign_ecdsa_sha256(tbs_payload.ptr, tbs_payload.len, signature,
			      &signature_len) != TEE_SUCCESS) {
		DMSG("Failed to sign payload");
		mempool_free(mempool_default, (void *)protected_header.ptr);
		mempool_free(mempool_default, (void *)tbs_payload.ptr);
		return;
	}

	/* Add the signature */
	QCBOREncode_AddBytes(context, signature_payload);

	/* Close top level array for COSE_Sign1 */
	QCBOREncode_CloseArray(context);
}

static void encode_cbor_evidence_wrapper(QCBOREncodeContext *context,
					 void *args)
{
	struct cbor_evidence_args *evidence_args =
		(struct cbor_evidence_args *)args;

	encode_cbor_evidence(context, evidence_args->ubc_eat_profile,
			     evidence_args->psa_client_id,
			     evidence_args->psa_security_lifecycle,
			     evidence_args->ubc_psa_implementation_id,
			     evidence_args->ubc_measurement_type,
			     evidence_args->ubc_signer_id,
			     evidence_args->ubc_psa_instance_id,
			     evidence_args->ubc_psa_nonce,
			     evidence_args->ubc_measurement_value);
}

static void encode_cose_evidence_wrapper(QCBOREncodeContext *context,
					 void *args)
{
	struct cose_evidence_args *cose_args =
		(struct cose_evidence_args *)args;

	encode_cose_evidence(context, cose_args->ubc_cbor_evidence);
}

static UsefulBufC
build_cbor_evidence(UsefulBufC ubc_eat_profile, int psa_client_id,
		    int psa_security_lifecycle,
		    UsefulBufC ubc_psa_implementation_id,
		    UsefulBufC ubc_measurement_type, UsefulBufC ubc_signer_id,
		    UsefulBufC ubc_psa_instance_id, UsefulBufC ubc_psa_nonce,
		    UsefulBufC ubc_measurement_value)
{
	struct cbor_evidence_args args = {
		.ubc_eat_profile = ubc_eat_profile,
		.psa_client_id = psa_client_id,
		.psa_security_lifecycle = psa_security_lifecycle,
		.ubc_psa_implementation_id = ubc_psa_implementation_id,
		.ubc_measurement_type = ubc_measurement_type,
		.ubc_signer_id = ubc_signer_id,
		.ubc_psa_instance_id = ubc_psa_instance_id,
		.ubc_psa_nonce = ubc_psa_nonce,
		.ubc_measurement_value = ubc_measurement_value,
	};

	return build_encoded_buffer(encode_cbor_evidence_wrapper, &args);
}

static UsefulBufC build_cose_evidence(UsefulBufC ubc_cbor_evidence)
{
	struct cose_evidence_args args = {
		.ubc_cbor_evidence = ubc_cbor_evidence,
	};

	return build_encoded_buffer(encode_cose_evidence_wrapper, &args);
}

UsefulBufC generate_cbor_evidence(const char *eat_profile,
				  int psa_client_id,
				  int psa_security_lifecycle,
				  const uint8_t *psa_implementation_id,
				  size_t psa_implementation_id_len,
				  const char *measurement_type,
				  const uint8_t *signer_id,
				  size_t signer_id_len,
				  const uint8_t *psa_instance_id,
				  size_t psa_instance_id_len,
				  const uint8_t *psa_nonce,
				  size_t psa_nonce_len,
				  const uint8_t *measurement_value,
				  size_t measurement_value_len)
{
	/* prepare usefulbufs because qcbor only accepts them */
	UsefulBufC ubc_eat_profile = UsefulBuf_FromSZ(eat_profile);
	UsefulBufC ubc_psa_implementation_id = { psa_implementation_id,
						 psa_implementation_id_len };
	UsefulBufC ubc_measurement_type = UsefulBuf_FromSZ(measurement_type);
	UsefulBufC ubc_signer_id = { signer_id, signer_id_len };
	UsefulBufC ubc_psa_instance_id = { psa_instance_id,
					   psa_instance_id_len };
	UsefulBufC ubc_psa_nonce = { psa_nonce, psa_nonce_len };
	UsefulBufC ubc_measurement_value = { measurement_value,
					     measurement_value_len };

	return build_cbor_evidence(ubc_eat_profile,
				   psa_client_id,
				   psa_security_lifecycle,
				   ubc_psa_implementation_id,
				   ubc_measurement_type,
				   ubc_signer_id,
				   ubc_psa_instance_id,
				   ubc_psa_nonce,
				   ubc_measurement_value);
}

UsefulBufC generate_cose_evidence(UsefulBufC ubc_cbor_evidence)
{
	return build_cose_evidence(ubc_cbor_evidence);
}
