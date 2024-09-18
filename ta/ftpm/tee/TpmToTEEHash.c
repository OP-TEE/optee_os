/* SPDX-License-Identifier: BSD-2-Clause */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <stdint.h>
#ifdef DEBUG_OUTPUT_TEE_HASH
#include <stdio.h>
#endif

// The typecasts in this file are not nice, and the function
// prototypes should take a PANY_HASH_STATE instead of void, but
// this seems to require a major re-organization of h-files.

/// @brief Initialize a SHA1 instance.
/// @param[out] state must point to a TEE_OperationHandle that is initialized by this function
void TEE_InitSha1(void* state)
{
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("InitSHA1(%p)\n", state);
#endif
    TEE_AllocateOperation((TEE_OperationHandle*)state, TEE_ALG_SHA1, TEE_MODE_DIGEST, 0);
}

/// @brief Initialize a SHA256 instance.
/// @param[out] state must point to a TEE_OperationHandle that is initialized by this function
void TEE_InitSha256(void* state)
{
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("InitSHA256(%p)\n", state);
#endif
    TEE_AllocateOperation((TEE_OperationHandle*)state, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
}

/// @brief Initialize a SHA384 instance.
/// @param[out] state must point to a TEE_OperationHandle that is initialized by this function
void TEE_InitSha384(void* state)
{
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("InitSHA384(%p)\n", state);
#endif
    TEE_AllocateOperation((TEE_OperationHandle*)state, TEE_ALG_SHA384, TEE_MODE_DIGEST, 0);
}

/// @brief Initialize a SHA512 instance.
/// @param[out] state must point to a TEE_OperationHandle that is initialized by this function
void TEE_InitSha512(void* state)
{
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("InitSHA512(%p)\n", state);
#endif
    TEE_AllocateOperation((TEE_OperationHandle*)state, TEE_ALG_SHA512, TEE_MODE_DIGEST, 0);
}

/// @brief Initialize an SM3 instance.
/// @param[out] state must point to a TEE_OperationHandle that is initialized by this function
void TEE_InitSm3(void* state)
{
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("InitSm3(%p)\n", state);
#endif
    TEE_AllocateOperation((TEE_OperationHandle*)state, TEE_ALG_SM3, TEE_MODE_DIGEST, 0);
}

/// @brief Finish a hash computation and release the hash instance
/// @param[in] state pointer to a TEE_OperationHandle that has been initialized by one of the TEE_InitHASH() functions (like TEE_InitSHA256)
/// @param[out] buffer pointer to a buffer for the hash output; the buffer must be large enough to hold this output
void TEE_FinalizeHash(void* state, uint8_t* buffer)
{
    TEE_OperationInfo op_info;
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("FinalizeHash(%p, %p)\n", state, buffer);
#endif
    TEE_GetOperationInfo(*(TEE_OperationHandle*)state, &op_info);
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("    algorithm %" PRIx32 ", mode %" PRIu32 ", digestLength %" PRIu32 "\n", op_info.algorithm, op_info.mode, op_info.digestLength);
#endif

    size_t hashLen = op_info.digestLength;
    TEE_DigestDoFinal(*(TEE_OperationHandle*)state, 0, 0, buffer, &hashLen);
    TEE_FreeOperation(*(TEE_OperationHandle*)state);
#ifdef DEBUG_OUTPUT_TEE_HASH
    printf("    ");
    for(uint32_t k = 0; k < hashLen; ++k)
    {
        printf("%.2x ", buffer[k]);
    }
    printf("\n");
#endif
}

/// @brief Feed data into a hash instance
/// @param[in] state pointer to a TEE_OperationHandle that has been initialized by one of the TEE_InitHASH() functions (like TEE_InitSHA256)
/// @param[in] chunk pointer to data to be fed into the hash instance
/// @param[in] chunk_size size of this data in bytes
/// @todo Is this wrapper really needed? It's a convenient hook for adding debug output, though.
void TEE_DigestUpdateWrapper(void* state, void* chunk, size_t chunk_size)
{
#ifdef DEBUG_OUTPUT_TEE_HASH
    TEE_OperationInfo op_info;
    printf("DigestUpdateWrapper(%p, %p, %zu)\n", state, chunk, chunk_size);
    TEE_GetOperationInfo(*(TEE_OperationHandle*)state, &op_info);
    printf("    algorithm %" PRIx32 ", mode %" PRIu32 ", digestLength %" PRIu32 "\n", op_info.algorithm, op_info.mode, op_info.digestLength);
#endif

    TEE_DigestUpdate(*(TEE_OperationHandle*)state, chunk, chunk_size);
}
