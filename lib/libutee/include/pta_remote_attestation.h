#ifndef __PTA_REMOTE_ATTESTATION_H
#define __PTA_REMOTE_ATTESTATION_H

#define PTA_REMOTE_ATTESTATION_UUID                                            \
    {                                                                          \
        0xa77955f9, 0xeea1, 0x44fd, {                                          \
            0xad, 0xd5, 0x4a, 0x9d, 0x96, 0x2a, 0xfc, 0xf5                     \
        }                                                                      \
    }

/*
 * Return a CBOR(COSE) evidence
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        Output buffer
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED  - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER   - Output buffer size less than required
 */
#define PTA_REMOTE_ATTESTATION_GET_CBOR_EVIDENCE 0x0

#endif /* __PTA_REMOTE_ATTESTATION_H */
