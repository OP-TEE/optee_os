#ifndef PTA_REMOTE_ATTESTATION_TA_CBOR_H
#define PTA_REMOTE_ATTESTATION_TA_CBOR_H

#include <qcbor_encode.h>
#include <stddef.h>
#include <stdint.h>

/* PSA claim keys */
/* https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token/13/ */
#define PSA_NONCE                   10
#define PSA_INSTANCE_ID             256
#define PSA_PROFILE_DEFINITION      265
#define PSA_ARM_RANGE_BASE          (2393)
#define PSA_CLIENT_ID               (PSA_ARM_RANGE_BASE + 1)
#define PSA_SECURITY_LIFECYCLE      (PSA_ARM_RANGE_BASE + 2)
#define PSA_IMPLEMENTATION_ID       (PSA_ARM_RANGE_BASE + 3)
#define PSA_BOOT_SEED               (PSA_ARM_RANGE_BASE + 4)
#define PSA_CERTIFICATION_REFERENCE (PSA_ARM_RANGE_BASE + 5)
#define PSA_SW_COMPONENTS           (PSA_ARM_RANGE_BASE + 6)
#define PSA_VERIFICATION_SERVICE    (PSA_ARM_RANGE_BASE + 7)

#define PSA_SW_COMPONENT_MEASUREMENT_TYPE  (1)
#define PSA_SW_COMPONENT_MEASUREMENT_VALUE (2)
#define PSA_SW_COMPONENT_VERSION           (4)
#define PSA_SW_COMPONENT_SIGNER_ID         (5)
#define PSA_SW_COMPONENT_MEASUREMENT_DESC  (6)

#define COSE_HEADER_PARAM_ALG              1
#define COSE_ALGORITHM_ES256               -7
#define COSE_SIG_CONTEXT_STRING_SIGNATURE1 "Signature1"

UsefulBufC
encode_evidence_to_cbor(const char *eat_profile, const int psa_client_id,
                        const int psa_security_lifecycle,
                        const uint8_t *psa_implementation_id,
                        size_t psa_implementation_id_len,
                        const char *measurement_type, const uint8_t *signer_id,
                        size_t signer_id_len, const uint8_t *psa_instance_id,
                        size_t psa_instance_id_len, const uint8_t *psa_nonce,
                        size_t psa_nonce_len, const uint8_t *measurement_value,
                        size_t mv_len, UsefulBuf cbor_evidence_buffer);

UsefulBufC generate_cose(UsefulBufC ubc_cbor_evidence,
                         UsefulBuf buffer_for_cose);

#endif /* PTA_REMOTE_ATTESTATION_TA_CBOR_H */
