// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Insitite of Information Security (IISEC)
 */

#include <kernel/pseudo_ta.h>
#include <pta_remote_attestation.h>

#include "cbor.h"
#include "hash.h"
#include <base64.h>
#include <stdlib.h>
#include <string.h>

#define PTA_NAME "remote_attestation.pta"

#define MAX_KEY_SIZE         4096
#define MAX_NONCE_SIZE       64
#define TEE_SHA256_HASH_SIZE 32

#define EAT_PROFILE     "http://arm.com/psa/2.0.0"
#define CLIENT_ID       1
#define LIFECYCLE       12288
#define MEASURMENT_TYPE "PRoT"
#define SIGNER_ID_LEN   32
#define INSTANCE_ID_LEN 33

/* clang-format off */
#define SIGNER_ID                                      \
    0xac, 0xbb, 0x11, 0xc7, 0xe4, 0xda, 0x21, 0x72,    \
    0x05, 0x52, 0x3c, 0xe4, 0xce, 0x1a, 0x24, 0x5a,    \
    0xe1, 0xa2, 0x39, 0xae, 0x3c, 0x6b, 0xfd, 0x9e,    \
    0x78, 0x71, 0xf7, 0xe5, 0xd8, 0xba, 0xe8, 0x6b
#define INSTANCE_ID                                    \
    0x01, 0xce, 0xeb, 0xae, 0x7b, 0x89, 0x27, 0xa3,    \
    0x22, 0x7e, 0x53, 0x03, 0xcf, 0x5e, 0x0f, 0x1f,    \
    0x7b, 0x34, 0xbb, 0x54, 0x2a, 0xd7, 0x25, 0x0a,    \
    0xc0, 0x3f, 0xbc, 0xde, 0x36, 0xec, 0x2f, 0x15,    \
    0x08
/* clang-format on */

static TEE_Result cmd_get_cbor_evidence(uint32_t param_types,
                                        TEE_Param params[TEE_NUM_PARAMS]) {
    const uint8_t *nonce = params[0].memref.buffer;
    const size_t nonce_sz = params[0].memref.size;
    uint8_t *output_buffer = params[1].memref.buffer;
    size_t *output_buffer_len = &params[1].memref.size;
    const uint8_t *psa_implementation_id = params[2].memref.buffer;
    const size_t psa_implementation_id_len = params[2].memref.size;
    TEE_Result status = TEE_SUCCESS;

    const char eat_profile[] = EAT_PROFILE;
    const int psa_client_id = CLIENT_ID;
    const int psa_security_lifecycle = LIFECYCLE;
    const char measurement_type[] = MEASURMENT_TYPE;
    const uint8_t signer_id[SIGNER_ID_LEN] = {SIGNER_ID};
    const uint8_t psa_instance_id[INSTANCE_ID_LEN] = {INSTANCE_ID};

    uint8_t measurement_value[TEE_SHA256_HASH_SIZE] = {0};
    size_t b64_measurement_value_len = TEE_SHA256_HASH_SIZE * 2;
    char b64_measurement_value[TEE_SHA256_HASH_SIZE * 2] = {0};

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_INOUT,
                                       TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    if (!nonce || !nonce_sz)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!output_buffer || !(*output_buffer_len))
        return TEE_ERROR_BAD_PARAMETERS;

    /* Calculate measurement hash of memory */
    status = get_hash_ta_memory(measurement_value, TEE_SHA256_HASH_SIZE);
    if (status != TEE_SUCCESS)
        return status;

    /* For debug print */
    if (base64_enc(measurement_value, TEE_SHA256_HASH_SIZE,
                   b64_measurement_value, &b64_measurement_value_len) != 1) {
        DMSG("Failed to encode measurement_value to base64");
        return TEE_ERROR_GENERIC;
    }
    b64_measurement_value[b64_measurement_value_len] = '\0';
    DMSG("b64_measurement_value: %s", b64_measurement_value);

    /* Encode evidence to CBOR */
    UsefulBuf_MAKE_STACK_UB(buffuer_for_cbor, 512);
    UsefulBufC ubc_cbor_evidence = encode_evidence_to_cbor(
        eat_profile, psa_client_id, psa_security_lifecycle,
        psa_implementation_id, psa_implementation_id_len, measurement_type,
        signer_id, SIGNER_ID_LEN, psa_instance_id, INSTANCE_ID_LEN, nonce,
        nonce_sz, measurement_value, TEE_SHA256_HASH_SIZE, buffuer_for_cbor);
    if (UsefulBuf_IsNULLC(ubc_cbor_evidence)) {
        DMSG("Failed to encode evidence to CBOR");
        return TEE_ERROR_GENERIC;
    }

    /* Sign the CBOR and generate a COSE evidence */
    UsefulBuf_MAKE_STACK_UB(buffer_for_cose, *output_buffer_len);
    UsefulBufC cose_evidence =
        generate_cose(ubc_cbor_evidence, buffer_for_cose);
    if (UsefulBuf_IsNULLC(cose_evidence)) {
        DMSG("Failed to encode CBOR to COSE");
        return TEE_ERROR_GENERIC;
    }

    /* Copy COSE evidence for return buffer */
    memcpy(output_buffer, cose_evidence.ptr, cose_evidence.len);
    *output_buffer_len = cose_evidence.len;

    return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
                                 uint32_t param_types,
                                 TEE_Param params[TEE_NUM_PARAMS]) {
    switch (cmd_id) {
    case PTA_REMOTE_ATTESTATION_GET_CBOR_EVIDENCE:
        return cmd_get_cbor_evidence(param_types, params);
    default:
        break;
    }
    return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_REMOTE_ATTESTATION_UUID, .name = PTA_NAME,
                   .flags = PTA_DEFAULT_FLAGS,
                   .invoke_command_entry_point = invoke_command);
