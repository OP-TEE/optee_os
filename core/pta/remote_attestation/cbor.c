#include "cbor.h"
#include "sign.h"
#include <kernel/pseudo_ta.h>

UsefulBufC
encode_evidence_to_cbor(const char *eat_profile, const int psa_client_id,
                        const int psa_security_lifecycle,
                        const uint8_t *psa_implementation_id,
                        size_t psa_implementation_id_len,
                        const char *measurement_type, const uint8_t *signer_id,
                        size_t signer_id_len, const uint8_t *psa_instance_id,
                        size_t psa_instance_id_len, const uint8_t *psa_nonce,
                        size_t psa_nonce_len, const uint8_t *measurement_value,
                        size_t mv_len, UsefulBuf cbor_evidence_buffer) {
    /* prepare usefulbufs because qcbor only accepts them */
    UsefulBufC ubc_eat_profile = UsefulBuf_FromSZ(eat_profile);
    UsefulBufC ubc_psa_implementation_id = {psa_implementation_id,
                                            psa_implementation_id_len};
    UsefulBufC ubc_measurement_type = UsefulBuf_FromSZ(measurement_type);
    UsefulBufC ubc_signer_id = {signer_id, signer_id_len};
    UsefulBufC ubc_psa_instance_id = {psa_instance_id, psa_instance_id_len};
    UsefulBufC ubc_psa_nonce = {psa_nonce, psa_nonce_len};
    UsefulBufC ubc_measurement_value = {measurement_value, mv_len};

    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, cbor_evidence_buffer);

    QCBOREncode_OpenMap(&encode_ctx);

    /* Profile Definition */
    QCBOREncode_AddTextToMapN(&encode_ctx, PSA_PROFILE_DEFINITION,
                              ubc_eat_profile);

    /* Client ID */
    QCBOREncode_AddInt64ToMapN(&encode_ctx, PSA_CLIENT_ID, psa_client_id);

    /* Security Lifecycle */
    QCBOREncode_AddInt64ToMapN(&encode_ctx, PSA_SECURITY_LIFECYCLE,
                               psa_security_lifecycle);

    /* Implementation ID */
    QCBOREncode_AddBytesToMapN(&encode_ctx, PSA_IMPLEMENTATION_ID,
                               ubc_psa_implementation_id);

    /* Software Components */
    QCBOREncode_OpenArrayInMapN(&encode_ctx, PSA_SW_COMPONENTS); /* [ */
    QCBOREncode_OpenMap(&encode_ctx);                            /* { */
    QCBOREncode_AddTextToMapN(&encode_ctx, PSA_SW_COMPONENT_MEASUREMENT_TYPE,
                              ubc_measurement_type);
    QCBOREncode_AddBytesToMapN(&encode_ctx, PSA_SW_COMPONENT_MEASUREMENT_VALUE,
                               ubc_measurement_value);
    QCBOREncode_AddBytesToMapN(&encode_ctx, PSA_SW_COMPONENT_SIGNER_ID,
                               ubc_signer_id);
    QCBOREncode_CloseMap(&encode_ctx);   /* } */
    QCBOREncode_CloseArray(&encode_ctx); /* ] */

    /* Nonce */
    QCBOREncode_AddBytesToMapN(&encode_ctx, PSA_NONCE, ubc_psa_nonce);

    /* Instance ID */
    QCBOREncode_AddBytesToMapN(&encode_ctx, PSA_INSTANCE_ID,
                               ubc_psa_instance_id);

    QCBOREncode_CloseMap(&encode_ctx);

    UsefulBufC cbor_evidence;
    QCBORError err = QCBOREncode_Finish(&encode_ctx, &cbor_evidence);
    if (err != QCBOR_SUCCESS) {
        return NULLUsefulBufC;
    } else {
        return cbor_evidence;
    }
}

UsefulBufC encode_protected_parameter(UsefulBuf buffer_for_protected_parameter);
UsefulBufC create_tbs(UsefulBufC protected_parameters, UsefulBufC aad,
                      UsefulBufC payload, UsefulBuf buffer_for_tbs);

UsefulBufC generate_cose(UsefulBufC ubc_cbor_evidence,
                         UsefulBuf buffer_for_cose) {
    QCBOREncodeContext cose_context;

    /* Add top level array for COSE_Sign1 */
    QCBOREncode_Init(&cose_context, buffer_for_cose);
    QCBOREncode_AddTag(&cose_context, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(&cose_context);

    /* Encode protected header */
    UsefulBuf_MAKE_STACK_UB(buffer_for_protected_parameter, 256);
    UsefulBufC protected_parameter =
        encode_protected_parameter(buffer_for_protected_parameter);
    if (UsefulBuf_IsNULLC(protected_parameter)) {
        DMSG("Failed to encode protected header payload");
        return NULLUsefulBufC;
    }

    /* Add protected header */
    QCBOREncode_AddBytes(&cose_context, protected_parameter);

    /* Add unprotected header (empty map) */
    QCBOREncode_OpenMap(&cose_context);
    QCBOREncode_CloseMap(&cose_context);

    /* Add the payload (evidence CBOR) */
    QCBOREncode_AddBytes(&cose_context, ubc_cbor_evidence);

    /* Encode "To Be Signed" payload */
    UsefulBuf_MAKE_STACK_UB(buffer_for_tbs, 1024);
    UsefulBufC tbs_payload = create_tbs(protected_parameter, NULLUsefulBufC,
                                        ubc_cbor_evidence, buffer_for_tbs);
    if (UsefulBuf_IsNULLC(tbs_payload)) {
        DMSG("Failed to encode to-be-signed payload");
        return NULLUsefulBufC;
    }

    /* Calculate a signature and add the signature to payload */
    uint8_t signature[64];
    size_t signature_len = 64;
    if (sign_ecdsa_sha256(tbs_payload.ptr, tbs_payload.len, signature,
                          &signature_len) != TEE_SUCCESS) {
        DMSG("Failed to sign payload");
        return NULLUsefulBufC;
    }

    /* Add the signature */
    UsefulBufC signature_payload = {signature, signature_len};
    QCBOREncode_AddBytes(&cose_context, signature_payload);

    /* Close top level array for COSE_Sign1 */
    QCBOREncode_CloseArray(&cose_context);

    UsefulBufC signed_cose;
    if (QCBOREncode_Finish(&cose_context, &signed_cose) != QCBOR_SUCCESS) {
        return NULLUsefulBufC;
    } else {
        return signed_cose;
    }
}

UsefulBufC
encode_protected_parameter(UsefulBuf buffer_for_protected_parameter) {
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, buffer_for_protected_parameter);

    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddInt64ToMapN(&context, COSE_HEADER_PARAM_ALG,
                               COSE_ALGORITHM_ES256);
    QCBOREncode_CloseMap(&context);

    UsefulBufC protected_parameter;
    if (QCBOREncode_Finish(&context, &protected_parameter) != QCBOR_SUCCESS) {
        return NULLUsefulBufC;
    } else {
        return protected_parameter;
    }
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
UsefulBufC create_tbs(UsefulBufC protected_parameters, UsefulBufC aad,
                      UsefulBufC payload, UsefulBuf buffer_for_tbs) {
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, buffer_for_tbs);

    QCBOREncode_OpenArray(&context);
    QCBOREncode_AddSZString(&context, COSE_SIG_CONTEXT_STRING_SIGNATURE1);
    QCBOREncode_AddBytes(&context, protected_parameters);
    QCBOREncode_AddBytes(&context, aad);
    QCBOREncode_AddBytes(&context, payload);
    QCBOREncode_CloseArray(&context);

    UsefulBufC tbs;
    if (QCBOREncode_Finish(&context, &tbs) != QCBOR_SUCCESS) {
        return NULLUsefulBufC;
    } else {
        return tbs;
    }
}
