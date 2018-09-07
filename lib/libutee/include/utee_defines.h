/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef UTEE_DEFINES_H
#define UTEE_DEFINES_H

#include <compiler.h>
#include <types_ext.h>

/*
 * Copied from TEE Internal API specificaion v1.0 table 6-9 "Structure of
 * Algorithm Identifier".
 */
#define TEE_MAIN_ALGO_MD5        0x01
#define TEE_MAIN_ALGO_SHA1       0x02
#define TEE_MAIN_ALGO_SHA224     0x03
#define TEE_MAIN_ALGO_SHA256     0x04
#define TEE_MAIN_ALGO_SHA384     0x05
#define TEE_MAIN_ALGO_SHA512     0x06
#define TEE_MAIN_ALGO_AES        0x10
#define TEE_MAIN_ALGO_DES        0x11
#define TEE_MAIN_ALGO_DES2       0x12
#define TEE_MAIN_ALGO_DES3       0x13
#define TEE_MAIN_ALGO_RSA        0x30
#define TEE_MAIN_ALGO_DSA        0x31
#define TEE_MAIN_ALGO_DH         0x32
#define TEE_MAIN_ALGO_ECDSA      0x41
#define TEE_MAIN_ALGO_ECDH       0x42
#define TEE_MAIN_ALGO_HKDF       0xC0 /* OP-TEE extension */
#define TEE_MAIN_ALGO_CONCAT_KDF 0xC1 /* OP-TEE extension */
#define TEE_MAIN_ALGO_PBKDF2     0xC2 /* OP-TEE extension */


#define TEE_CHAIN_MODE_ECB_NOPAD        0x0
#define TEE_CHAIN_MODE_CBC_NOPAD        0x1
#define TEE_CHAIN_MODE_CTR              0x2
#define TEE_CHAIN_MODE_CTS              0x3
#define TEE_CHAIN_MODE_XTS              0x4
#define TEE_CHAIN_MODE_CBC_MAC_PKCS5    0x5
#define TEE_CHAIN_MODE_CMAC             0x6
#define TEE_CHAIN_MODE_CCM              0x7
#define TEE_CHAIN_MODE_GCM              0x8
#define TEE_CHAIN_MODE_PKCS1_PSS_MGF1   0x9	/* ??? */

	/* Bits [31:28] */
#define TEE_ALG_GET_CLASS(algo)         (((algo) >> 28) & 0xF)

#define TEE_ALG_GET_KEY_TYPE(algo, with_private_key) \
        (TEE_ALG_GET_MAIN_ALG(algo) | \
            ((with_private_key) ? 0xA1000000 : 0xA0000000))

	/* Bits [7:0] */
#define TEE_ALG_GET_MAIN_ALG(algo)      ((algo) & 0xFF)

	/* Bits [11:8] */
#define TEE_ALG_GET_CHAIN_MODE(algo)    (((algo) >> 8) & 0xF)

	/* Bits [15:12] */
#define TEE_ALG_GET_DIGEST_HASH(algo)   (((algo) >> 12) & 0xF)

	/* Bits [23:20] */
#define TEE_ALG_GET_INTERNAL_HASH(algo) (((algo) >> 20) & 0x7)

	/* Return hash algorithm based on main hash */
#define TEE_ALG_HASH_ALGO(main_hash) \
        (TEE_OPERATION_DIGEST << 28 | (main_hash))

	/* Extract internal hash and return hash algorithm */
#define TEE_INTERNAL_HASH_TO_ALGO(algo) \
                TEE_ALG_HASH_ALGO(TEE_ALG_GET_INTERNAL_HASH(algo))

	/* Extract digest hash and return hash algorithm */
#define TEE_DIGEST_HASH_TO_ALGO(algo) \
                TEE_ALG_HASH_ALGO(TEE_ALG_GET_DIGEST_HASH(algo))

/* Return HMAC algorithm based on main hash */
#define TEE_ALG_HMAC_ALGO(main_hash) \
	(TEE_OPERATION_MAC << 28 | (main_hash))

#define TEE_AES_BLOCK_SIZE  16UL
#define TEE_DES_BLOCK_SIZE  8UL

#define TEE_AES_MAX_KEY_SIZE    32UL

	/* SHA-512 */
#ifndef TEE_MD5_HASH_SIZE
typedef enum {
	TEE_MD5_HASH_SIZE = 16,
	TEE_SHA1_HASH_SIZE = 20,
	TEE_SHA224_HASH_SIZE = 28,
	TEE_SHA256_HASH_SIZE = 32,
	TEE_SHA384_HASH_SIZE = 48,
	TEE_SHA512_HASH_SIZE = 64,
	TEE_MD5SHA1_HASH_SIZE = (TEE_MD5_HASH_SIZE + TEE_SHA1_HASH_SIZE),
	TEE_MAX_HASH_SIZE = 64,
} t_hash_size;
#endif

typedef enum {
	TEE_CURVE_SIZE_192 = 20,
	TEE_CURVE_SIZE_224 = 28,
	TEE_CURVE_SIZE_256 = 32,
	TEE_CURVE_SIZE_384 = 48,
	TEE_CURVE_SIZE_521 = 66,
} t_curve_size;

#define TEE_MAC_SIZE_AES_CBC_MAC_NOPAD
#define TEE_MAC_SIZE_AES_CBC_MAC_PKCS5
#define TEE_MAC_SIZE_AES_CMAC
#define TEE_MAC_SIZE_DES_CBC_MAC_PKCS5

/*
 * Bit indicating that the attribute is a value attribute
 * See TEE Internal API specificaion v1.0 table 6-12 "Partial Structure of
 * Attribute Identifier"
 */


#ifdef __compiler_bswap64
#define TEE_U64_BSWAP(x) __compiler_bswap64((x))
#else
#define TEE_U64_BSWAP(x) ((uint64_t)( \
        (((uint64_t)(x) & UINT64_C(0xff00000000000000ULL)) >> 56) | \
        (((uint64_t)(x) & UINT64_C(0x00ff000000000000ULL)) >> 40) | \
        (((uint64_t)(x) & UINT64_C(0x0000ff0000000000ULL)) >> 24) | \
        (((uint64_t)(x) & UINT64_C(0x000000ff00000000ULL)) >>  8) | \
        (((uint64_t)(x) & UINT64_C(0x00000000ff000000ULL)) <<  8) | \
        (((uint64_t)(x) & UINT64_C(0x0000000000ff0000ULL)) << 24) | \
        (((uint64_t)(x) & UINT64_C(0x000000000000ff00ULL)) << 40) | \
        (((uint64_t)(x) & UINT64_C(0x00000000000000ffULL)) << 56)))
#endif

#ifdef __compiler_bswap32
#define TEE_U32_BSWAP(x) __compiler_bswap32((x))
#else
#define TEE_U32_BSWAP(x) ((uint32_t)( \
        (((uint32_t)(x) & UINT32_C(0xff000000)) >> 24) | \
        (((uint32_t)(x) & UINT32_C(0x00ff0000)) >>  8) | \
        (((uint32_t)(x) & UINT32_C(0x0000ff00)) <<  8) | \
        (((uint32_t)(x) & UINT32_C(0x000000ff)) << 24)))
#endif

#ifdef __compiler_bswap16
#define TEE_U16_BSWAP(x) __compiler_bswap16((x))
#else
#define TEE_U16_BSWAP(x) ((uint16_t)( \
        (((uint16_t)(x) & UINT16_C(0xff00)) >> 8) | \
        (((uint16_t)(x) & UINT16_C(0x00ff)) << 8)))
#endif

/* If we we're on a big endian platform we'll have to update these */
#define TEE_U64_FROM_BIG_ENDIAN(x)  TEE_U64_BSWAP(x)
#define TEE_U32_FROM_BIG_ENDIAN(x)  TEE_U32_BSWAP(x)
#define TEE_U16_FROM_BIG_ENDIAN(x)  TEE_U16_BSWAP(x)
#define TEE_U64_TO_BIG_ENDIAN(x)    TEE_U64_BSWAP(x)
#define TEE_U32_TO_BIG_ENDIAN(x)    TEE_U32_BSWAP(x)
#define TEE_U16_TO_BIG_ENDIAN(x)    TEE_U16_BSWAP(x)

#define TEE_TIME_MILLIS_BASE    1000

#define TEE_TIME_LT(t1, t2)				\
    (((t1).seconds == (t2).seconds) ?			\
        ((t1).millis < (t2).millis) :			\
        ((t1).seconds < (t2).seconds))

#define TEE_TIME_LE(t1, t2)				\
    (((t1).seconds == (t2).seconds) ?			\
        ((t1).millis <= (t2).millis) :			\
        ((t1).seconds <= (t2).seconds))

#define TEE_TIME_ADD(t1, t2, dst) do {                      \
        (dst).seconds = (t1).seconds + (t2).seconds;        \
        (dst).millis = (t1).millis + (t2).millis;           \
        if ((dst).millis >= TEE_TIME_MILLIS_BASE) {         \
            (dst).seconds++;                                \
            (dst).millis -= TEE_TIME_MILLIS_BASE;           \
        }                                                   \
    } while (0)

#define TEE_TIME_SUB(t1, t2, dst) do {                      \
        (dst).seconds = (t1).seconds - (t2).seconds;        \
        if ((t1).millis < (t2).millis) {                    \
            (dst).seconds--;                                \
            (dst).millis = (t1).millis + TEE_TIME_MILLIS_BASE - (t2).millis;\
        } else {                                            \
            (dst).millis = (t1).millis - (t2).millis;       \
        }                                                   \
    } while (0)

/* ------------------------------------------------------------ */
/* OTP mapping                                                  */
/* ------------------------------------------------------------ */
#define HW_UNIQUE_KEY_WORD1      (8)
#define HW_UNIQUE_KEY_LENGTH     (16)
#define HW_UNIQUE_KEY_WORD2      (HW_UNIQUE_KEY_WORD1 + 1)
#define HW_UNIQUE_KEY_WORD3      (HW_UNIQUE_KEY_WORD1 + 2)
#define HW_UNIQUE_KEY_WORD4      (HW_UNIQUE_KEY_WORD1 + 3)

#define UTEE_SE_READER_PRESENT			(1 << 0)
#define UTEE_SE_READER_TEE_ONLY			(1 << 1)
#define UTEE_SE_READER_SELECT_RESPONE_ENABLE	(1 << 2)

#endif /* UTEE_DEFINES_H */
