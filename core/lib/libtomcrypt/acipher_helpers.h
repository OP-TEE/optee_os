/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#ifndef ACIPHER_HELPERS_H
#define ACIPHER_HELPERS_H

#include <crypto/crypto.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tomcrypt_private.h>
#include <types_ext.h>

static inline bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(_CFG_CORE_LTC_BIGNUM_MAX_BITS);

	return *s;
}

static inline TEE_Result convert_ltc_verify_status(int ltc_res, int ltc_stat)
{
	switch (ltc_res) {
	case CRYPT_OK:
		if (ltc_stat == 1)
			return TEE_SUCCESS;
		else
			return TEE_ERROR_SIGNATURE_INVALID;
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}

#ifdef _CFG_CORE_LTC_ECC
TEE_Result ecc_populate_ltc_private_key(ecc_key *ltc_key,
					struct ecc_keypair *key,
					uint32_t algo, size_t *key_size_bytes);
TEE_Result ecc_populate_ltc_public_key(ecc_key *ltc_key,
				       struct ecc_public_key *key,
				       uint32_t algo, size_t *key_size_bytes);
#endif

/* Write bignum to fixed size buffer in big endian order */
#define mp_to_unsigned_bin2(a, b, c) \
        do { \
                void *_a = (a); \
                mp_to_unsigned_bin(_a, (b) + (c) - mp_unsigned_bin_size(_a)); \
        } while(0)

#ifdef _CFG_CORE_LTC_SM2_DSA
TEE_Result sm2_ltc_dsa_sign(uint32_t algo, struct ecc_keypair *key,
			    const uint8_t *msg, size_t msg_len, uint8_t *sig,
			    size_t *sig_len);

TEE_Result sm2_ltc_dsa_verify(uint32_t algo, struct ecc_public_key *key,
			      const uint8_t *msg, size_t msg_len,
			      const uint8_t *sig, size_t sig_len);
#else
static inline TEE_Result
sm2_ltc_dsa_sign(uint32_t algo __unused, struct ecc_keypair *key __unused,
		 const uint8_t *msg __unused, size_t msg_len __unused,
		 uint8_t *sig __unused, size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
sm2_ltc_dsa_verify(uint32_t algo __unused, struct ecc_public_key *key __unused,
		   const uint8_t *msg __unused, size_t msg_len __unused,
		   const uint8_t *sig __unused, size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif

#ifdef _CFG_CORE_LTC_SM2_PKE
TEE_Result sm2_ltc_pke_decrypt(struct ecc_keypair *key, const uint8_t *src,
			       size_t src_len, uint8_t *dst, size_t *dst_len);

TEE_Result sm2_ltc_pke_encrypt(struct ecc_public_key *key, const uint8_t *src,
			       size_t src_len, uint8_t *dst, size_t *dst_len);

#else
static inline TEE_Result sm2_ltc_pke_decrypt(struct ecc_keypair *key __unused,
					     const uint8_t *src __unused,
					     size_t src_len __unused,
					     uint8_t *dst __unused,
					     size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
sm2_ltc_pke_encrypt(struct ecc_public_key *key __unused,
		    const uint8_t *src __unused, size_t src_len __unused,
		    uint8_t *dst __unused, size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif
#endif /* ACIPHER_HELPERS_H */
