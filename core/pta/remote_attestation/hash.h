#ifndef PTA_REMOTE_ATTESTATION_TA_HASH_H
#define PTA_REMOTE_ATTESTATION_TA_HASH_H

#include <tee_api_types.h>

TEE_Result get_hash_ta_memory(uint8_t *out, size_t out_sz);

#endif /* PTA_REMOTE_ATTESTATION_TA_HASH_H */
