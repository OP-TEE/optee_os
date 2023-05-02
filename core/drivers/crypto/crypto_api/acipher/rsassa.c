// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * RSA Signature Software common implementation.
 * Functions preparing and/or verifying the signature
 * encoded string.
 *
 * PKCS #1 v2.1: RSA Cryptography Standard
 * https://www.ietf.org/rfc/rfc3447.txt
 */
#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <drvcrypt_asn1_oid.h>
#include <drvcrypt_math.h>
#include <malloc.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>
#include <util.h>

#include "local.h"

/*
 * PKCS#1 V1.5 - Encode the message in Distinguished Encoding Rules
 * (DER) format.
 * Refer to EMSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
 *
 * @ssa_data  RSA data to encode
 * @EM        [out] Encoded Message
 */
static TEE_Result emsa_pkcs1_v1_5_encode(struct drvcrypt_rsa_ssa *ssa_data,
					 struct drvcrypt_buf *EM)
{
	const struct drvcrypt_oid *hash_oid = NULL;
	size_t ps_size = 0;
	uint8_t *buf = NULL;

	hash_oid = drvcrypt_get_alg_hash_oid(ssa_data->hash_algo);
	if (!hash_oid)
		return TEE_ERROR_NOT_SUPPORTED;

	/*
	 * Calculate the PS size
	 *  EM Size (modulus size) - 3 bytes - DigestInfo DER format size
	 */
	ps_size = ssa_data->key.n_size - 3;
	ps_size -= ssa_data->digest_size;
	ps_size -= 10 + hash_oid->asn1_length;

	CRYPTO_TRACE("PS size = %zu (n %zu)", ps_size, ssa_data->key.n_size);

	/*
	 * EM = 0x00 || 0x01 || PS || 0x00 || T
	 *
	 * where T represent the message DigestInfo in DER:
	 *    DigestInfo ::= SEQUENCE {
	 *                digestAlgorithm AlgorithmIdentifier,
	 *                digest OCTET STRING
	 *                }
	 *
	 * T  Length = digest length + oid length
	 * EM Length = T Length + 11 + PS Length
	 */
	buf = EM->data;

	/* Set the EM first byte to 0x00 */
	*buf++ = 0x00;

	/* Set the EM second byte to 0x01 */
	*buf++ = 0x01;

	/* Fill PS with 0xFF */
	memset(buf, UINT8_MAX, ps_size);
	buf += ps_size;

	/* Set the Byte after PS to 0x00 */
	*buf++ = 0x00;

	/*
	 * Create the DigestInfo DER Sequence
	 *
	 *  DigestInfo ::= SEQUENCE {
	 *                digestAlgorithm AlgorithmIdentifier,
	 *                digest OCTET STRING
	 *                }
	 *
	 */
	/* SEQUENCE { */
	*buf++ = DRVCRYPT_ASN1_SEQUENCE | DRVCRYPT_ASN1_CONSTRUCTED;
	*buf++ = 0x08 + hash_oid->asn1_length + ssa_data->digest_size;

	/* digestAlgorithm AlgorithmIdentifier */
	*buf++ = DRVCRYPT_ASN1_SEQUENCE | DRVCRYPT_ASN1_CONSTRUCTED;
	*buf++ = 0x04 + hash_oid->asn1_length;
	*buf++ = DRVCRYPT_ASN1_OID;
	*buf++ = hash_oid->asn1_length;

	/* digest OCTET STRING */
	memcpy(buf, hash_oid->asn1, hash_oid->asn1_length);
	buf += hash_oid->asn1_length;
	*buf++ = DRVCRYPT_ASN1_NULL;
	*buf++ = 0x00;
	*buf++ = DRVCRYPT_ASN1_OCTET_STRING;
	*buf++ = ssa_data->digest_size;
	/* } */

	memcpy(buf, ssa_data->message.data, ssa_data->digest_size);

	CRYPTO_DUMPBUF("Encoded Message", EM->data, (size_t)EM->length);

	return TEE_SUCCESS;
}

/*
 * PKCS#1 V1.5 - Encode the message in Distinguished Encoding Rules
 * (DER) format.
 * Refer to EMSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
 *
 * @ssa_data  RSA data to encode
 * @EM        [out] Encoded Message
 */
static TEE_Result
emsa_pkcs1_v1_5_encode_noasn1(struct drvcrypt_rsa_ssa *ssa_data,
			      struct drvcrypt_buf *EM)
{
	size_t ps_size = 0;
	uint8_t *buf = NULL;

	/*
	 * Calculate the PS size
	 *  EM Size (modulus size) - 3 bytes - Message Length
	 */
	ps_size = ssa_data->key.n_size - 3;

	if (ps_size < ssa_data->message.length)
		return TEE_ERROR_BAD_PARAMETERS;

	ps_size -= ssa_data->message.length;

	CRYPTO_TRACE("PS size = %zu (n %zu)", ps_size, ssa_data->key.n_size);

	/*
	 * EM = 0x00 || 0x01 || PS || 0x00 || T
	 *
	 * T  Length = message length
	 * EM Length = T Length + PS Length
	 */
	buf = EM->data;

	/* Set the EM first byte to 0x00 */
	*buf++ = 0x00;

	/* Set the EM second byte to 0x01 */
	*buf++ = 0x01;

	/* Fill PS with 0xFF */
	memset(buf, UINT8_MAX, ps_size);
	buf += ps_size;

	/* Set the Byte after PS to 0x00 */
	*buf++ = 0x00;

	memcpy(buf, ssa_data->message.data, ssa_data->message.length);

	CRYPTO_DUMPBUF("Encoded Message", EM->data, EM->length);

	return TEE_SUCCESS;
}

/*
 * PKCS#1 V1.5 - Signature of RSA message and encodes the signature.
 * Refer to RSASSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
 *
 * @ssa_data   [in/out] RSA data to sign / Signature
 */
static TEE_Result rsassa_pkcs1_v1_5_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_buf EM = { };
	struct drvcrypt_rsa_ed rsa_data = { };
	struct drvcrypt_rsa *rsa = NULL;

	EM.length = ssa_data->key.n_size;
	EM.data = malloc(EM.length);
	if (!EM.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Encode the Message */
	if (ssa_data->algo != TEE_ALG_RSASSA_PKCS1_V1_5)
		ret = emsa_pkcs1_v1_5_encode(ssa_data, &EM);
	else
		ret = emsa_pkcs1_v1_5_encode_noasn1(ssa_data, &EM);

	if (ret != TEE_SUCCESS)
		goto out;

	/*
	 * RSA Encrypt/Decrypt are doing the same operation except
	 * that decrypt takes a RSA Private key in parameter
	 */
	rsa_data.key.key = ssa_data->key.key;
	rsa_data.key.isprivate = true;
	rsa_data.key.n_size = ssa_data->key.n_size;

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (!rsa) {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}

	/* Prepare the decryption data parameters */
	rsa_data.rsa_id = DRVCRYPT_RSASSA_PKCS_V1_5;
	rsa_data.message.data = ssa_data->signature.data;
	rsa_data.message.length = ssa_data->signature.length;
	rsa_data.cipher.data = EM.data;
	rsa_data.cipher.length = EM.length;
	rsa_data.hash_algo = ssa_data->hash_algo;
	rsa_data.algo = ssa_data->algo;

	ret = rsa->decrypt(&rsa_data);

	/* Set the message decrypted size */
	ssa_data->signature.length = rsa_data.message.length;

out:
	free(EM.data);

	return ret;
}

/*
 * PKCS#1 V1.5 - Verification of the RSA message's signature.
 * Refer to RSASSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
 *
 * @ssa_data   [int/out] RSA data signed and encoded signature
 */
static TEE_Result rsassa_pkcs1_v1_5_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_buf EM = { };
	struct drvcrypt_buf EM_gen = { };
	struct drvcrypt_rsa_ed rsa_data = { };
	struct drvcrypt_rsa *rsa = NULL;

	EM.length = ssa_data->key.n_size;
	EM.data = malloc(EM.length);

	if (!EM.data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_verify;
	}

	EM_gen.length = ssa_data->key.n_size;
	EM_gen.data = malloc(EM.length);

	if (!EM_gen.data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_verify;
	}

	/*
	 * RSA Encrypt/Decrypt are doing the same operation except
	 * that the encrypt takes a RSA Public key in parameter
	 */
	rsa_data.key.key = ssa_data->key.key;
	rsa_data.key.isprivate = false;
	rsa_data.key.n_size = ssa_data->key.n_size;

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		rsa_data.rsa_id = DRVCRYPT_RSASSA_PKCS_V1_5;
		rsa_data.message.data = ssa_data->signature.data;
		rsa_data.message.length = ssa_data->signature.length;
		rsa_data.cipher.data = EM.data;
		rsa_data.cipher.length = EM.length;
		rsa_data.hash_algo = ssa_data->hash_algo;
		ret = rsa->encrypt(&rsa_data);

		/* Set the cipher size */
		EM.length = rsa_data.cipher.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (ret != TEE_SUCCESS)
		goto end_verify;

	/* Encode the Message */
	if (ssa_data->algo != TEE_ALG_RSASSA_PKCS1_V1_5)
		ret = emsa_pkcs1_v1_5_encode(ssa_data, &EM_gen);
	else
		ret = emsa_pkcs1_v1_5_encode_noasn1(ssa_data, &EM_gen);

	if (ret != TEE_SUCCESS)
		goto end_verify;

	/* Check if EM decrypted and EM re-generated are identical */
	ret = TEE_ERROR_SIGNATURE_INVALID;
	if (EM.length == EM_gen.length) {
		if (!memcmp(EM.data, EM_gen.data, EM.length))
			ret = TEE_SUCCESS;
	}

end_verify:
	free(EM.data);
	free(EM_gen.data);

	return ret;
}

/*
 * PSS - Encode the message using a Probabilistic Signature Scheme (PSS)
 * Refer to EMSA-PSS (encoding) chapter of the PKCS#1 v2.1
 *
 * @ssa_data  RSA data to encode
 * @emBits    EM size in bits
 * @EM        [out] Encoded Message
 */
static TEE_Result emsa_pss_encode(struct drvcrypt_rsa_ssa *ssa_data,
				  size_t emBits, struct drvcrypt_buf *EM)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct drvcrypt_rsa_mgf mgf_data = { };
	struct drvcrypt_buf hash = { };
	struct drvcrypt_buf dbMask = { };
	struct drvcrypt_buf DB = { };
	size_t db_size = 0;
	size_t ps_size = 0;
	size_t msg_size = 0;
	uint8_t *buf = NULL;
	uint8_t *msg_db = NULL;
	uint8_t *salt = NULL;
	struct drvcrypt_mod_op mod_op = { };

	/*
	 * Build EM = maskedDB || H || 0xbc
	 *
	 * where
	 *    maskedDB = DB xor dbMask
	 *       DB     = PS || 0x01 || salt
	 *       dbMask = MGF(H, emLen - hLen - 1)
	 *
	 *    H  = Hash(M')
	 *       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * PS size = emLen - sLen - hLen - 2 (may be = 0)
	 */

	/*
	 * Calculate the M' and DB size to allocate a temporary buffer
	 * used for both object
	 */
	ps_size = EM->length - ssa_data->digest_size - ssa_data->salt_len - 2;
	db_size = EM->length - ssa_data->digest_size - 1;
	msg_size = 8 + ssa_data->digest_size + ssa_data->salt_len;

	CRYPTO_TRACE("PS Len = %zu, DB Len = %zu, M' Len = %zu", ps_size,
		     db_size, msg_size);

	msg_db = malloc(MAX(db_size, msg_size));
	if (!msg_db)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ssa_data->salt_len) {
		salt = malloc(ssa_data->salt_len);

		if (!salt) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_pss_encode;
		}
	}

	/*
	 * Step 4 and 5
	 * Generate the M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * where
	 *   mHash is the input message (already hash)
	 *   salt is a random number of salt_len (input data) can be empty
	 */
	buf = msg_db;

	memset(buf, 0, 8);
	buf += 8;

	memcpy(buf, ssa_data->message.data, ssa_data->message.length);
	buf += ssa_data->message.length;

	/* Get salt random number if salt length not 0 */
	if (ssa_data->salt_len) {
		ret = crypto_rng_read(salt, ssa_data->salt_len);
		CRYPTO_TRACE("Get salt of %zu bytes (ret = 0x%08" PRIx32 ")",
			     ssa_data->salt_len, ret);
		if (ret != TEE_SUCCESS)
			goto end_pss_encode;

		memcpy(buf, salt, ssa_data->salt_len);
	}

	/*
	 * Step 6
	 * Hash the M' generated new message
	 * H = hash(M')
	 */
	hash.data = &EM->data[db_size];
	hash.length = ssa_data->digest_size;

	ret = tee_hash_createdigest(ssa_data->hash_algo, msg_db, msg_size,
				    hash.data, hash.length);

	CRYPTO_TRACE("H = hash(M') returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_encode;

	CRYPTO_DUMPBUF("H = hash(M')", hash.data, hash.length);

	/*
	 * Step 7 and 8
	 *   DB = PS || 0x01 || salt
	 */
	buf = msg_db;
	if (ps_size)
		memset(buf, 0, ps_size);
	buf += ps_size;
	*buf++ = 0x01;

	if (ssa_data->salt_len)
		memcpy(buf, salt, ssa_data->salt_len);

	DB.data = msg_db;
	DB.length = db_size;

	CRYPTO_DUMPBUF("DB", DB.data, DB.length);

	/*
	 * Step 9
	 * Generate a Mask of the seed value
	 * dbMask = MGF(H, emLen - hLen - 1)
	 *
	 * Note: Will use the same buffer for the dbMask and maskedDB
	 *       maskedDB is in the EM output
	 */
	dbMask.data = EM->data;
	dbMask.length = db_size;

	mgf_data.hash_algo = ssa_data->hash_algo;
	mgf_data.digest_size = ssa_data->digest_size;
	mgf_data.seed.data = hash.data;
	mgf_data.seed.length = hash.length;
	mgf_data.mask.data = dbMask.data;
	mgf_data.mask.length = dbMask.length;
	ret = ssa_data->mgf(&mgf_data);

	CRYPTO_TRACE("dbMask = MGF(H, emLen - hLen - 1) returned 0x%08" PRIx32,
		     ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_encode;

	CRYPTO_DUMPBUF("dbMask", dbMask.data, dbMask.length);

	/*
	 * Step 10
	 * maskedDB = DB xor dbMask
	 */
	mod_op.n.length = dbMask.length;
	mod_op.a.data = DB.data;
	mod_op.a.length = DB.length;
	mod_op.b.data = dbMask.data;
	mod_op.b.length = dbMask.length;
	mod_op.result.data = dbMask.data;
	mod_op.result.length = dbMask.length;

	ret = drvcrypt_xor_mod_n(&mod_op);
	CRYPTO_TRACE("maskedDB = DB xor dbMask returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_encode;

	CRYPTO_DUMPBUF("maskedDB", dbMask.data, dbMask.length);

	/*
	 * Step 11
	 * Set the leftmost 8emLen - emBits of the leftmost octet
	 * in maskedDB to 0'
	 */
	EM->data[0] &= (UINT8_MAX >> ((EM->length * 8) - emBits));

	/*
	 * Step 12
	 * EM = maskedDB || H || 0xbc
	 */
	EM->data[EM->length - 1] = 0xbc;

	CRYPTO_DUMPBUF("EM", EM->data, EM->length);

	ret = TEE_SUCCESS;
end_pss_encode:
	free(msg_db);
	free(salt);

	return ret;
}

/*
 * PSS - Verify the message using a Probabilistic Signature Scheme (PSS)
 * Refer to EMSA-PSS (verification) chapter of the PKCS#1 v2.1
 *
 * @ssa_data  RSA data to encode
 * @emBits    EM size in bits
 * @EM        [out] Encoded Message
 */
static TEE_Result emsa_pss_verify(struct drvcrypt_rsa_ssa *ssa_data,
				  size_t emBits, struct drvcrypt_buf *EM)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct drvcrypt_rsa_mgf mgf_data = { };
	struct drvcrypt_buf hash = { };
	struct drvcrypt_buf hash_gen = { };
	size_t db_size = 0;
	size_t ps_size = 0;
	size_t msg_size = 0;
	uint8_t *msg_db = NULL;
	uint8_t *salt = NULL;
	uint8_t *buf = NULL;
	struct drvcrypt_mod_op mod_op = { };

	/*
	 * EM = maskedDB || H || 0xbc
	 *
	 * where
	 *    maskedDB = DB xor dbMask
	 *       DB     = PS || 0x01 || salt
	 *       dbMask = MGF(H, emLen - hLen - 1)
	 *
	 *    H  = Hash(M')
	 *       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * PS size = emLen - sLen - hLen - 2 (may be = 0)
	 */

	/*
	 * Calculate the M' and DB size to allocate a temporary buffer
	 * used for both object
	 */
	ps_size = EM->length - ssa_data->digest_size - ssa_data->salt_len - 2;
	db_size = EM->length - ssa_data->digest_size - 1;
	msg_size = 8 + ssa_data->digest_size + ssa_data->salt_len;

	CRYPTO_TRACE("PS Len = %zu, DB Len = %zu, M' Len = %zu", ps_size,
		     db_size, msg_size);

	msg_db = malloc(MAX(db_size, msg_size));
	if (!msg_db)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Step 4
	 * Check if rightmost octet of EM is 0xbc
	 */
	if (EM->data[EM->length - 1] != 0xbc) {
		CRYPTO_TRACE("rigthmost octet != 0xbc (0x%" PRIX8 ")",
			     EM->data[EM->length - 1]);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto end_pss_verify;
	}

	/*
	 * Step 6
	 * Check if the leftmost 8emLen - emBits of the leftmost octet
	 * in maskedDB are 0's
	 */
	if (EM->data[0] & ~(UINT8_MAX >> (EM->length * 8 - emBits))) {
		CRYPTO_TRACE("Error leftmost octet maskedDB not 0's");
		CRYPTO_TRACE("EM[0] = 0x%" PRIX8
			     " - EM Len = %zu, emBits = %zu",
			     EM->data[0], EM->length, emBits);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto end_pss_verify;
	}

	hash.data = &EM->data[db_size];
	hash.length = ssa_data->digest_size;

	/*
	 * Step 7
	 * dbMask = MGF(H, emLen - hLen - 1)
	 *
	 * Note: Will use the same buffer for the dbMask and DB
	 */
	mgf_data.hash_algo = ssa_data->hash_algo;
	mgf_data.digest_size = ssa_data->digest_size;
	mgf_data.seed.data = hash.data;
	mgf_data.seed.length = hash.length;
	mgf_data.mask.data = msg_db;
	mgf_data.mask.length = db_size;
	ret = ssa_data->mgf(&mgf_data);

	CRYPTO_TRACE("dbMask = MGF(H, emLen - hLen - 1) returned 0x%08" PRIx32,
		     ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_verify;

	CRYPTO_DUMPBUF("dbMask", msg_db, db_size);

	/*
	 * Step 8
	 * DB = maskedDB xor dbMask
	 *
	 *
	 * Note: maskedDB is in the EM input
	 */
	mod_op.n.length = db_size;
	mod_op.a.data = EM->data;
	mod_op.a.length = db_size;
	mod_op.b.data = msg_db;
	mod_op.b.length = db_size;
	mod_op.result.data = msg_db;
	mod_op.result.length = db_size;

	ret = drvcrypt_xor_mod_n(&mod_op);
	CRYPTO_TRACE("DB = maskedDB xor dbMask returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_verify;

	/*
	 * Step 9
	 * Set the leftmost 8emLen - emBits of the leftmost octet in
	 * DB to zero
	 */
	*msg_db &= UINT8_MAX >> (EM->length * 8 - emBits);

	CRYPTO_DUMPBUF("DB", msg_db, db_size);

	/*
	 * Step 10
	 * Expected to have
	 *       DB     = PS || 0x01 || salt
	 *
	 * PS must be 0
	 * PS size = emLen - sLen - hLen - 2 (may be = 0)
	 */
	buf = msg_db;
	while (buf < msg_db + ps_size) {
		if (*buf++ != 0) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto end_pss_verify;
		}
	}

	if (*buf++ != 0x01) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto end_pss_verify;
	}

	/*
	 * Step 11
	 * Get the salt value
	 */
	if (ssa_data->salt_len) {
		salt = malloc(ssa_data->salt_len);
		if (!salt) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_pss_verify;
		}

		memcpy(salt, buf, ssa_data->salt_len);
	}

	/*
	 * Step 12
	 * Generate the M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * where
	 *   mHash is the input message (already hash)
	 *   salt is a random number of salt_len (input data) can be empty
	 */
	buf = msg_db;

	memset(buf, 0, 8);
	buf += 8;

	memcpy(buf, ssa_data->message.data, ssa_data->message.length);
	buf += ssa_data->message.length;

	if (ssa_data->salt_len)
		memcpy(buf, salt, ssa_data->salt_len);

	/*
	 * Step 13
	 * Hash the M' generated new message
	 * H' = hash(M')
	 *
	 * Note: reuse the msg_db buffer as Hash result
	 */
	hash_gen.data = msg_db;
	hash_gen.length = ssa_data->digest_size;

	ret = tee_hash_createdigest(ssa_data->hash_algo, msg_db, msg_size,
				    hash_gen.data, hash_gen.length);

	CRYPTO_TRACE("H' = hash(M') returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_verify;

	CRYPTO_DUMPBUF("H' = hash(M')", hash_gen.data, hash_gen.length);

	/*
	 * Step 14
	 * Compare H and H'
	 */
	ret = TEE_ERROR_SIGNATURE_INVALID;
	if (!memcmp(hash_gen.data, hash.data, hash_gen.length))
		ret = TEE_SUCCESS;

end_pss_verify:
	free(msg_db);
	free(salt);

	return ret;
}

/*
 * PSS - Signature of RSA message and encodes the signature.
 * Refer to RSASSA-PSS chapter of the PKCS#1 v2.1
 *
 * @ssa_data   [in/out] RSA data to sign / Signature
 */
static TEE_Result rsassa_pss_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct rsa_keypair *key = NULL;
	struct drvcrypt_buf EM = { };
	size_t modBits = 0;
	struct drvcrypt_rsa_ed rsa_data = { };
	struct drvcrypt_rsa *rsa = NULL;

	key = ssa_data->key.key;

	/* Get modulus length in bits */
	modBits = crypto_bignum_num_bits(key->n);
	if (modBits <= 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * EM Length = (modBits - 1) / 8
	 * if (modBits - 1) is not divisible by 8, one more byte is needed
	 */
	modBits--;
	EM.length = ROUNDUP(modBits, 8) / 8;

	if (EM.length < ssa_data->digest_size + ssa_data->salt_len + 2)
		return TEE_ERROR_BAD_PARAMETERS;

	EM.data = malloc(EM.length);
	if (!EM.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	CRYPTO_TRACE("modBits = %zu, hence EM Length = %zu", modBits + 1,
		     EM.length);

	/* Encode the Message */
	ret = emsa_pss_encode(ssa_data, modBits, &EM);
	CRYPTO_TRACE("EMSA PSS Encode returned 0x%08" PRIx32, ret);

	/*
	 * RSA Encrypt/Decrypt are doing the same operation
	 * expect that the decrypt takes a RSA Private key in parameter
	 */
	if (ret == TEE_SUCCESS) {
		rsa_data.key.key = ssa_data->key.key;
		rsa_data.key.isprivate = true;
		rsa_data.key.n_size = ssa_data->key.n_size;

		rsa = drvcrypt_get_ops(CRYPTO_RSA);
		if (rsa) {
			/* Prepare the decryption data parameters */
			rsa_data.rsa_id = DRVCRYPT_RSASSA_PSS;
			rsa_data.message.data = ssa_data->signature.data;
			rsa_data.message.length = ssa_data->signature.length;
			rsa_data.cipher.data = EM.data;
			rsa_data.cipher.length = EM.length;
			rsa_data.algo = ssa_data->algo;

			ret = rsa->decrypt(&rsa_data);

			/* Set the message decrypted size */
			ssa_data->signature.length = rsa_data.message.length;
		} else {
			ret = TEE_ERROR_NOT_IMPLEMENTED;
		}
	}
	free(EM.data);

	return ret;
}

/*
 * PSS - Signature verification of RSA message.
 * Refer to RSASSA-PSS chapter of the PKCS#1 v2.1
 *
 * @ssa_data   [in/out] RSA Signature vs. message to verify
 */
static TEE_Result rsassa_pss_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct rsa_public_key *key = NULL;
	struct drvcrypt_buf EM = { };
	size_t modBits = 0;
	struct drvcrypt_rsa_ed rsa_data = { };
	struct drvcrypt_rsa *rsa = NULL;

	key = ssa_data->key.key;

	/* Get modulus length in bits */
	modBits = crypto_bignum_num_bits(key->n);
	if (modBits <= 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * EM Length = (modBits - 1) / 8
	 * if (modBits - 1) is not divisible by 8, one more byte is needed
	 */
	modBits--;
	EM.length = ROUNDUP(modBits, 8) / 8;

	if (EM.length < ssa_data->digest_size + ssa_data->salt_len + 2)
		return TEE_ERROR_BAD_PARAMETERS;

	EM.data = malloc(EM.length);
	if (!EM.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	CRYPTO_TRACE("modBits = %zu, hence EM Length = %zu", modBits + 1,
		     EM.length);

	/*
	 * RSA Encrypt/Decrypt are doing the same operation
	 * expect that the encrypt takes a RSA Public key in parameter
	 */
	rsa_data.key.key = ssa_data->key.key;
	rsa_data.key.isprivate = false;
	rsa_data.key.n_size = ssa_data->key.n_size;

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		rsa_data.rsa_id = DRVCRYPT_RSASSA_PSS;
		rsa_data.message.data = ssa_data->signature.data;
		rsa_data.message.length = ssa_data->signature.length;
		rsa_data.cipher.data = EM.data;
		rsa_data.cipher.length = EM.length;
		rsa_data.algo = ssa_data->algo;

		ret = rsa->encrypt(&rsa_data);

		/* Set the cipher size */
		EM.length = rsa_data.cipher.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		goto end_pss_verify;
	}

	if (ret == TEE_SUCCESS) {
		/* Verify the Message */
		ret = emsa_pss_verify(ssa_data, modBits, &EM);
		CRYPTO_TRACE("EMSA PSS Verify returned 0x%08" PRIx32, ret);
	} else {
		CRYPTO_TRACE("RSA NO PAD returned 0x%08" PRIx32, ret);
		ret = TEE_ERROR_SIGNATURE_INVALID;
	}

end_pss_verify:
	free(EM.data);

	return ret;
}

TEE_Result drvcrypt_rsassa_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return rsassa_pkcs1_v1_5_sign(ssa_data);

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return rsassa_pss_sign(ssa_data);

	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result drvcrypt_rsassa_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return rsassa_pkcs1_v1_5_verify(ssa_data);

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return rsassa_pss_verify(ssa_data);

	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}
