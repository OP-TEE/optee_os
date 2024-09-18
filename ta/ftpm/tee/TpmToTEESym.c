/* SPDX-License-Identifier: BSD-2-Clause */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <stdint.h>
#ifdef DEBUG_OUTPUT_TEE_SYM
#  include <stdio.h>
#endif

#ifdef DEBUG_OUTPUT_TEE_SYM
#  define DEBUG_PRINT_RESULT(f) printf("    " #f " returns %" PRIx32 "\n", f)
#else
#  define DEBUG_PRINT_RESULT(f) f
#endif

/// @todo It is ugly to repeat these definitions here rather than just include TpmToTEESym.h, but this would require a major re-structuring of h-files.

/// @brief The TEE does not export a key schedule, so this is not really a key schedule but rather a copy of the key.
typedef struct
{
    uint16_t keySizeInBytes;
    uint8_t  key[32];
} tpmKeyScheduleAES;

/// @brief The TEE does not export a key schedule, so this is not really a key schedule but rather a copy of the key.
typedef struct
{
    uint16_t keySizeInBytes;
    uint8_t  key[24];
} tpmKeyScheduleTDES;

/// @brief The TEE does not export a key schedule, so this is not really a key schedule but rather a copy of the key.
typedef struct
{
    uint16_t keySizeInBytes;
    uint8_t  key[16];
} tpmKeyScheduleSM4;

/// @brief Set AES key.
/// @param[out] key_schedule pointer to space for storing the key schedule
/// @param[in] key pointer to the key
/// @param[in] keySizeInBytes length of the key in bytes
/// @return 0 if ok, any other value otherwise
/// @todo There is no `finalize` function, so we can't allocate  the key schedule here, because we could never free it.
int TEE_SetKeyAES(
    tpmKeyScheduleAES* key_schedule, const uint8_t* key, uint16_t keySizeInBytes)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_SetKeyAES(%p, %p, %d)\n", key_schedule, key, (int)keySizeInBytes);
    printf("    key = ");
    for(uint16_t k = 0; k < keySizeInBytes; ++k)
    {
        printf("%.2x", (unsigned int)(key[k]));
    }
    printf("\n");
#endif
    if(((keySizeInBytes == 16) || (keySizeInBytes == 24) || (keySizeInBytes == 32))
       && (keySizeInBytes <= sizeof(key_schedule->key)))
    {
        key_schedule->keySizeInBytes = keySizeInBytes;
        memcpy(key_schedule->key, key, keySizeInBytes);
        return 0;
    }
    else
    {
        return 1;
    }
}

/// @brief Set DES key.
/// @param[out] key_schedule pointer to space for storing the key schedule
/// @param[in] key pointer to the key
/// @param[in] keySizeInBytes length of the key in bytes
/// @return 0 if ok, any other value otherwise
/// @todo There is no `finalize` function, so we can't allocate  the key schedule here, because we could never free it.
int TEE_SetKeyTDES(
    tpmKeyScheduleTDES* key_schedule, const uint8_t* key, uint16_t keySizeInBytes)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_SetKeyTDES(%p, %p, %d)\n", key_schedule, key, (int)keySizeInBytes);
    printf("    key = ");
    for(uint16_t k = 0; k < keySizeInBytes; ++k)
    {
        printf("%.2x", (unsigned int)(key[k]));
    }
    printf("\n");
#endif
    if(((keySizeInBytes == 16) || (keySizeInBytes == 24))
       && (keySizeInBytes <= sizeof(key_schedule->key)))
    {
        key_schedule->keySizeInBytes = keySizeInBytes;
        memcpy(key_schedule->key, key, keySizeInBytes);
        return 0;
    }
    else
    {
        return 1;
    }
}

/// @brief Set SM4 key.
/// @param[out] key_schedule pointer to space for storing the key schedule
/// @param[in] key pointer to the key
/// @param[in] keySizeInBytes length of the key in bytes
/// @return 0 if ok, any other value otherwise
/// @todo There is no `finalize` function, so we can't allocate  the key schedule here, because we could never free it.
int TEE_SetKeySM4(
    tpmKeyScheduleSM4* key_schedule, const uint8_t* key, uint16_t keySizeInBytes)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_SetKeySM4(%p, %p, %d)\n", key_schedule, key, (int)keySizeInBytes);
    printf("    key = ");
    for(uint16_t k = 0; k < keySizeInBytes; ++k)
    {
        printf("%.2x", (unsigned int)(key[k]));
    }
    printf("\n");
#endif
    if((keySizeInBytes == 16) && (keySizeInBytes <= sizeof(key_schedule->key)))
    {
        key_schedule->keySizeInBytes = keySizeInBytes;
        memcpy(key_schedule->key, key, keySizeInBytes);
        return 0;
    }
    else
    {
        return 1;
    }
}

typedef enum
{
    ALGO_AES,
    ALGO_TDES,
    ALGO_SM4
} SymAlgoType;

typedef enum
{
    OP_ENCRYPT,
    OP_DECRYPT
} SymOp;

/// @brief Encrypt or decrypt one block of data with AES, TDES or SM4
/// @param[out] out pointer to space for one block of output data (16 bytes for AES and SM4, 8 bytes for TDES)
/// @param[in] algo algorithm
/// @param[in] op operation
/// @param[in] key pointer to key
/// @param[in] keySizeInBytes length of key in bytes
/// @param[in] in pointer to one block of input data (16 bytes for AES and SM4, 8 bytes for TDES)
static void TEE_sym(uint8_t*       out,
                    SymAlgoType    algo,
                    SymOp          op,
                    const uint8_t* key,
                    uint16_t       keySizeInBytes,
                    const uint8_t* in)
{
    uint32_t     objectType;
    uint32_t     mode;
    uint32_t     algorithm;
    unsigned int blockSize;
    switch(algo)
    {
        case ALGO_AES:
            objectType = TEE_TYPE_AES;
            algorithm  = TEE_ALG_AES_ECB_NOPAD;
            blockSize  = 16;
            break;
        case ALGO_TDES:
            objectType = TEE_TYPE_DES3;
            algorithm  = TEE_ALG_DES3_ECB_NOPAD;
            blockSize  = 8;
            break;
        case ALGO_SM4:
            objectType = TEE_TYPE_SM4;
            algorithm  = TEE_ALG_SM4_ECB_NOPAD;
            blockSize  = 16;
            break;
        default:
            /// @todo Do error handling!
            break;
    }
    switch(op)
    {
        case OP_ENCRYPT:
            mode = TEE_MODE_ENCRYPT;
            break;
        case OP_DECRYPT:
            mode = TEE_MODE_DECRYPT;
            break;
        default:
            /// @todo Do error handling!
            break;
    }

    TEE_ObjectHandle object;
    DEBUG_PRINT_RESULT(
        TEE_AllocateTransientObject(objectType, 8 * keySizeInBytes, &object));
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keySizeInBytes);
    DEBUG_PRINT_RESULT(TEE_PopulateTransientObject(object, &attr, 1));
    TEE_OperationHandle operation;
    DEBUG_PRINT_RESULT(
        TEE_AllocateOperation(&operation, algorithm, mode, 8 * keySizeInBytes));
    DEBUG_PRINT_RESULT(TEE_SetOperationKey(operation, object));

    TEE_CipherInit(operation, 0, 0);
    size_t outlen = blockSize;
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_CipherDoFinal(operation, in, blockSize, out, &outlen) - BEFORE CALL\n");
    printf("    in  = ");
    for(size_t k = 0; k < blockSize; ++k)
    {
        printf("%.2x", in[k]);
    }
    printf("\n");
    printf("    out = ");
    for(size_t k = 0; k < blockSize; ++k)
    {
        printf("%.2x", out[k]);
    }
    printf("\n");
#endif
    DEBUG_PRINT_RESULT(TEE_CipherDoFinal(operation, in, blockSize, out, &outlen));
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_CipherDoFinal(operation, in, blockSize, out, &outlen) - AFTER CALL\n");
    printf("    in  = ");
    for(size_t k = 0; k < blockSize; ++k)
    {
        printf("%.2x", in[k]);
    }
    printf("\n");
    printf("    out = ");
    for(size_t k = 0; k < blockSize; ++k)
    {
        printf("%.2x", out[k]);
    }
    printf("\n");
#endif

    TEE_FreeOperation(operation);
    TEE_FreeTransientObject(object);
    /// @todo Do proper error handling.
}

/// @brief Encrypt a single 16 byte block of data with AES.
/// @param out pointer to 16 bytes space for output
/// @param key_schedule pointer to the key schedule, initialized with TEE_SetKeyAES().
/// @param in pointer to 16 bytes input
/// @todo This is a very thin wrapper that may not be needed.
void TEE_AESEncrypt(
    uint8_t* out, const tpmKeyScheduleAES* key_schedule, const uint8_t* in)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_AESEncrypt(%p, %p, %p)\n", out, key_schedule, in);
    printf("    in  = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
    TEE_sym(out,
            ALGO_AES,
            OP_ENCRYPT,
            key_schedule->key,
            key_schedule->keySizeInBytes,
            in);
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("    out = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(out[k]));
    }
    printf("\n");
#endif
}

/// @brief Decrypt a single 16 byte block of data with AES.
/// @param out pointer to 16 bytes space for output
/// @param key_schedule pointer to the key schedule, initialized with TEE_SetKeyAES().
/// @param in pointer to 16 bytes input
/// @todo This is a very thin wrapper that may not be needed.
void TEE_AESDecrypt(
    uint8_t* out, const tpmKeyScheduleAES* key_schedule, const uint8_t* in)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_AESDecrypt(%p, %p, %p)\n", out, key_schedule, in);
    printf("    in  = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
    TEE_sym(out,
            ALGO_AES,
            OP_DECRYPT,
            key_schedule->key,
            key_schedule->keySizeInBytes,
            in);
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("    out = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
}

/// @brief Encrypt a single 8 byte block of data with TDES.
/// @param out pointer to 8 bytes space for output
/// @param key_schedule pointer to the key schedule, initialized with TEE_SetKeyTDES().
/// @param in pointer to 8 bytes input
/// @todo This is a very thin wrapper that may not be needed.
void TEE_TDESEncrypt(
    uint8_t* out, const tpmKeyScheduleTDES* key_schedule, const uint8_t* in)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_TDESEncrypt(%p, %p, %p)\n", out, key_schedule, in);
    printf("    in  = ");
    for(size_t k = 0; k < 8; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
    TEE_sym(out,
            ALGO_TDES,
            OP_ENCRYPT,
            key_schedule->key,
            key_schedule->keySizeInBytes,
            in);
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("    out = ");
    for(size_t k = 0; k < 8; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
}

/// @brief Decrypt a single 8 byte block of data with TDES.
/// @param out pointer to 8 bytes space for output
/// @param key_schedule pointer to the key schedule, initialized with TEE_SetKeyTDES().
/// @param in pointer to 8 bytes input
/// @todo This is a very thin wrapper that may not be needed.
void TEE_TDESDecrypt(
    uint8_t* out, const tpmKeyScheduleTDES* key_schedule, const uint8_t* in)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_TDESDecrypt(%p, %p, %p)\n", out, key_schedule, in);
    printf("    in  = ");
    for(size_t k = 0; k < 8; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
    TEE_sym(out,
            ALGO_TDES,
            OP_DECRYPT,
            key_schedule->key,
            key_schedule->keySizeInBytes,
            in);
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("    out = ");
    for(size_t k = 0; k < 8; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
}

/// @brief Encrypt a single 16 byte block of data with SM4.
/// @param out pointer to 16 bytes space for output
/// @param key_schedule pointer to the key schedule, initialized with TEE_SetKeySM4().
/// @param in pointer to 16 bytes input
/// @todo This is a very thin wrapper that may not be needed.
void TEE_SM4Encrypt(
    uint8_t* out, const tpmKeyScheduleSM4* key_schedule, const uint8_t* in)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_SM4Encrypt(%p, %p, %p)\n", out, key_schedule, in);
    printf("    in  = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
    TEE_sym(out,
            ALGO_SM4,
            OP_ENCRYPT,
            key_schedule->key,
            key_schedule->keySizeInBytes,
            in);
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("    out = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
}

/// @brief Decrypt a single 16 byte block of data with SM4.
/// @param out pointer to 16 bytes space for output
/// @param key_schedule pointer to the key schedule, initialized with TEE_SetKeySM4().
/// @param in pointer to 16 bytes input
/// @todo This is a very thin wrapper that may not be needed.
void TEE_SM4Decrypt(
    uint8_t* out, const tpmKeyScheduleSM4* key_schedule, const uint8_t* in)
{
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("TEE_SM4Decrypt(%p, %p, %p)\n", out, key_schedule, in);
    printf("    in  = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
    TEE_sym(out,
            ALGO_SM4,
            OP_DECRYPT,
            key_schedule->key,
            key_schedule->keySizeInBytes,
            in);
#ifdef DEBUG_OUTPUT_TEE_SYM
    printf("    out = ");
    for(size_t k = 0; k < 16; ++k)
    {
        printf("%.2x", (unsigned int)(in[k]));
    }
    printf("\n");
#endif
}
