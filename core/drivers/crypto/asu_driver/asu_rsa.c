// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drivers/amd/asu_client.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <initcall.h>
#include <inttypes.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee/cache.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#ifndef CACHELINE_LEN
#define CACHELINE_LEN				64U
#endif

/* ASU RSA command IDs */
#define ASU_RSA_PUBLIC_ENCRYPT_CMD_ID		0U
#define ASU_RSA_PRIVATE_DECRYPT_CMD_ID		1U
#define ASU_RSA_OAEP_ENC_SHA2_CMD_ID		3U
#define ASU_RSA_OAEP_DEC_SHA2_CMD_ID		4U
#define ASU_RSA_OAEP_ENC_SHA3_CMD_ID		5U
#define ASU_RSA_OAEP_DEC_SHA3_CMD_ID		6U
#define ASU_RSA_PSS_SIGN_GEN_SHA2_CMD_ID	7U
#define ASU_RSA_PSS_SIGN_VER_SHA2_CMD_ID	8U
#define ASU_RSA_PSS_SIGN_GEN_SHA3_CMD_ID	9U
#define ASU_RSA_PSS_SIGN_VER_SHA3_CMD_ID	10U

/* ASU KeyManager command IDs used for RSA key generation */
#define ASU_KM_GEN_RSA_KEY_PAIR_CMD_ID		6U

/* RSA key size */
#define ASU_RSA_2048_KEY_SIZE			256U
#define ASU_RSA_3072_KEY_SIZE			384U
#define ASU_RSA_4096_KEY_SIZE			512U

/* RSA key sizes (bytes) */
#define ASU_RSA_MAX_PRIV_EXP_LEN		512U
#define ASU_RSA_MAX_PUB_EXP_LEN			4U
#define ASU_RSA_MAX_MOD_LEN			512U

/* ASU RSA input data type */
#define ASU_RSA_HASHED_INPUT_DATA		1U

/* SHA types */
#define ASU_RSA_SHA2_TYPE			2U
#define ASU_RSA_SHA3_TYPE			3U

/* SHA modes */
#define ASU_RSA_SHA_MODE_256			0U
#define ASU_RSA_SHA_MODE_384			1U
#define ASU_RSA_SHA_MODE_512			2U

/* RSA operation status codes */
#define ASU_RSA_PSS_SIGNATURE_VERIFIED		0x3FAU
#define ASU_RSA_DECRYPTION_SUCCESS		0x3FBU
#define ASU_RSA_PSS_RIGHT_MOST_CMP_FAIL		0x0C4U
#define ASU_RSA_PSS_HASH_CMP_FAIL		0x0C8U
#define ASU_RSA_PSS_SIGN_VER_ERROR		0x0C9U

#define ASU_RSA_MAX_KEY_SIZE_IN_WORDS		128U
#define ASU_RSA_MAX_KEY_SIZE_BITS		4096U
#define ASU_RSA_BITS_PER_BYTE			8U
#define ASU_RSA_FW_STATUS_CODE_MASK		0x3FFU
#define ASU_RSA_WORD_LEN_IN_BYTES		4U
#define ASU_RSA_RESP_DATA_WORD0_INDEX		1U
#define ASU_RSA_RESP_ADDITIONAL_STATUS_IDX	ASU_COMMAND_RESP_ARGS
#define ASU_RSA_RESP_ARRAY_WORDS		(ASU_COMMAND_RESP_ARGS + 1U)

/* KeyManager request constants */
#define ASU_RSA_KM_VAULT_ID			0U
#define ASU_RSA_KM_KEY_TYPE_RSA_PVT		2U
#define ASU_RSA_KM_KEY_USE_CASE_ALL		7U
#define ASU_RSA_KM_USAGE_COUNT_NON_DEPLETING	0xFFFFFFFFU

/* RSA key buffer lengths */
#define ASU_RSA_PUB_KEY_BUF_LEN		(ASU_RSA_MAX_MOD_LEN + \
					ASU_RSA_MAX_PUB_EXP_LEN)
#define ASU_RSA_PRIV_KEY_BUF_LEN	(ASU_RSA_MAX_MOD_LEN + \
					ASU_RSA_MAX_PRIV_EXP_LEN)

/* Public key payload expected by ASU FW */
struct asu_rsa_pub_key_comp {
	uint32_t key_size;
	uint32_t modulus[ASU_RSA_MAX_KEY_SIZE_IN_WORDS];
	uint32_t pub_exp;
};

/* Private key payload expected by ASU FW */
struct asu_rsa_pvt_key_comp {
	struct asu_rsa_pub_key_comp pub_key;
	uint32_t pvt_exp[ASU_RSA_MAX_KEY_SIZE_IN_WORDS];
	uint32_t prime_comp_or_totient[ASU_RSA_MAX_KEY_SIZE_IN_WORDS];
	uint32_t prime_comp_or_totient_present;
};

/* Base ASU RSA command payload */
struct asu_rsa_common_params {
	uint64_t input_data_addr;
	uint64_t output_data_addr;
	uint64_t expo_comp_addr;
	uint64_t key_comp_addr;
	uint64_t output_len_addr;
	uint32_t len;
	uint32_t output_data_len;
	uint32_t key_size;
	uint32_t key_id;
};

/* ASU payload for RSA commands with padding algorithm */
struct asu_rsa_padding_params {
	struct asu_rsa_common_params rsa_op;
	uint64_t signature_data_addr;
	uint32_t signature_len;
	uint32_t salt_len;
	uint8_t sha_type;
	uint8_t sha_mode;
	uint8_t input_data_type;
	uint8_t reserved[5];
};

/* ASU payload for RSA OAEP commands */
struct asu_rsa_oaep_padding_params {
	struct asu_rsa_common_params rsa_op;
	uint64_t optional_label_addr;
	uint32_t optional_label_size;
	uint8_t sha_type;
	uint8_t sha_mode;
	uint8_t reserved[2];
};

struct asu_rsa_resp_cbctx {
	uint32_t *resp_data; /* Response buffer from ASUFW */
};

/* KeyManager AES key object */
struct asu_rsa_aes_key_object {
	uint64_t key_address;
	uint32_t key_size;
	uint32_t key_src;
	uint32_t key_id;
	uint8_t reserved[4];
};

/* KeyManager key metadata */
struct asu_rsa_km_key_metadata {
	uint16_t key_id;
	uint8_t key_type;
	uint8_t vault_id;
	uint8_t key_use_case;
	uint8_t key_attributes;
	uint16_t length;
	uint32_t epoch_time;
	uint32_t usage_count;
};

/* KeyManager parameters */
struct asu_rsa_km_params {
	struct asu_rsa_km_key_metadata key_metadata;
	struct asu_rsa_aes_key_object aes_key_obj;
	uint64_t key_object_addr;
	uint64_t key_id_addr;
	uint32_t wrapped_input_len;
	uint8_t reserved[4];
};

/* Key object returned by KeyManager RSA key-pair generation. */
struct asu_rsa_keypair_object {
	uint32_t modulus[ASU_RSA_MAX_KEY_SIZE_IN_WORDS];
	uint32_t pvt_exp[ASU_RSA_MAX_KEY_SIZE_IN_WORDS];
	uint32_t prime1[ASU_RSA_MAX_KEY_SIZE_IN_WORDS / 2U];
	uint32_t prime2[ASU_RSA_MAX_KEY_SIZE_IN_WORDS / 2U];
	uint32_t dp[ASU_RSA_MAX_KEY_SIZE_IN_WORDS / 2U];
	uint32_t dq[ASU_RSA_MAX_KEY_SIZE_IN_WORDS / 2U];
	uint32_t qinv[ASU_RSA_MAX_KEY_SIZE_IN_WORDS / 2U];
};

/* Calculate the length of the RSA key-pair blob */
static size_t asu_rsa_keypair_blob_len(size_t size_bytes)
{
	size_t prime_bytes = size_bytes / 2U;

	return (size_bytes * 2U) + (prime_bytes * 5U);
}

/**
 * asu_rsa_resp_capture_cb() - Capture RSA response data
 * @cbptr: Callback pointer
 * @resp: ASU response buffer
 *
 * Return: TEE_SUCCESS on success, or TEE_ERROR_BAD_PARAMETERS on invalid input
 */
static TEE_Result asu_rsa_resp_capture_cb(void *cbptr,
					  struct asu_resp_buf *resp)
{
	struct asu_rsa_resp_cbctx *ctx = cbptr;

	if (!ctx || !resp)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ctx->resp_data) {
		memcpy(ctx->resp_data, resp->arg, sizeof(resp->arg));
		ctx->resp_data[ASU_RSA_RESP_ADDITIONAL_STATUS_IDX] =
			resp->additionalstatus;
	}

	return TEE_SUCCESS;
}

/**
 * asu_rsa_bn2bin_pad() - Serialize bignum into fixed-size buffer
 * @size: Destination buffer size in bytes
 * @from: Source bignum
 * @to: Destination buffer (zero padded on the left)
 */
static void asu_rsa_bn2bin_pad(size_t size, struct bignum *from, uint8_t *to)
{
	size_t len = 0;

	if (!from || !to || !size)
		return;

	len = crypto_bignum_num_bytes(from);
	memset(to, 0, size);
	crypto_bignum_bn2bin(from, to + size - len);
}

/**
 * asu_rsa_alloc_align_buf() - Allocate zeroed cacheline-aligned memory
 * @len: Requested payload length
 * @alloc_len: Returns aligned allocation length when non-NULL
 *
 * Return: Aligned buffer on success, or NULL on allocation failure.
 */
static void *asu_rsa_alloc_align_buf(size_t len, size_t *alloc_len)
{
	size_t aligned_len = ROUNDUP(len, CACHELINE_LEN);
	void *buf = memalign(CACHELINE_LEN, aligned_len);

	if (!buf)
		return NULL;

	memset(buf, 0, aligned_len);
	if (alloc_len)
		*alloc_len = aligned_len;

	return buf;
}

/**
 * asu_rsa_sha_cfg_from_hash_algo() - Map TEE hash algorithm to ASU hash tuple
 * @hash_algo: TEE hash algorithm identifier
 * @sha_type: Returned ASU hash family
 * @sha_mode: Returned ASU hash mode
 *
 * Return: TEE_SUCCESS on success else error code.
 */
static TEE_Result asu_rsa_sha_cfg_from_hash_algo(uint32_t hash_algo,
						 uint8_t *sha_type,
						 uint8_t *sha_mode)
{
	if (!sha_type || !sha_mode) {
		EMSG("Invalid SHA cfg output pointers");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (hash_algo) {
	case TEE_ALG_SHA256:
		*sha_type = ASU_RSA_SHA2_TYPE;
		*sha_mode = ASU_RSA_SHA_MODE_256;
		break;
	case TEE_ALG_SHA384:
		*sha_type = ASU_RSA_SHA2_TYPE;
		*sha_mode = ASU_RSA_SHA_MODE_384;
		break;
	case TEE_ALG_SHA512:
		*sha_type = ASU_RSA_SHA2_TYPE;
		*sha_mode = ASU_RSA_SHA_MODE_512;
		break;
	case TEE_ALG_SHA3_256:
		*sha_type = ASU_RSA_SHA3_TYPE;
		*sha_mode = ASU_RSA_SHA_MODE_256;
		break;
	case TEE_ALG_SHA3_384:
		*sha_type = ASU_RSA_SHA3_TYPE;
		*sha_mode = ASU_RSA_SHA_MODE_384;
		break;
	case TEE_ALG_SHA3_512:
		*sha_type = ASU_RSA_SHA3_TYPE;
		*sha_mode = ASU_RSA_SHA_MODE_512;
		break;
	default:
		EMSG("Unsupported hash algo=0x%08" PRIx32, hash_algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;
}

/**
 * asu_rsa_sha_cfg_from_oaep_algo() - Derive ASU hash tuple from OAEP algorithm
 * @algo: TEE OAEP algorithm identifier
 * @sha_type: Returned ASU hash family
 * @sha_mode: Returned ASU hash mode
 *
 * Return: TEE_SUCCESS on success else error code.
 */
static TEE_Result asu_rsa_sha_cfg_from_oaep_algo(uint32_t algo,
						 uint8_t *sha_type,
						 uint8_t *sha_mode)
{
	switch (algo) {
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		return asu_rsa_sha_cfg_from_hash_algo(TEE_ALG_SHA256,
					sha_type, sha_mode);
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		return asu_rsa_sha_cfg_from_hash_algo(TEE_ALG_SHA384,
					sha_type, sha_mode);
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		return asu_rsa_sha_cfg_from_hash_algo(TEE_ALG_SHA512,
					sha_type, sha_mode);
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_256:
		return asu_rsa_sha_cfg_from_hash_algo(TEE_ALG_SHA3_256,
					sha_type, sha_mode);
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_384:
		return asu_rsa_sha_cfg_from_hash_algo(TEE_ALG_SHA3_384,
					sha_type, sha_mode);
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_512:
		return asu_rsa_sha_cfg_from_hash_algo(TEE_ALG_SHA3_512,
					sha_type, sha_mode);
	default:
		EMSG("Unsupported OAEP algo=0x%08" PRIx32, algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/**
 * asu_rsa_pack_public_key() - Convert OP-TEE RSA public key to ASU key payload
 * @pub: OP-TEE RSA public key
 * @n_size: Modulus size in bytes
 * @key_comp: Output ASU public key structure
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result
asu_rsa_pack_public_key(struct rsa_public_key *pub, size_t n_size,
			struct asu_rsa_pub_key_comp *key_comp)
{
	uint8_t n_bin[ASU_RSA_MAX_MOD_LEN] = { };
	uint8_t e_bin[ASU_RSA_MAX_PUB_EXP_LEN] = { };
	size_t words = n_size / sizeof(uint32_t);
	size_t exp_len = 0;

	if (!pub || !key_comp || !n_size || n_size > ASU_RSA_MAX_MOD_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (words > ASU_RSA_MAX_KEY_SIZE_IN_WORDS)
		return TEE_ERROR_BAD_PARAMETERS;

	exp_len = crypto_bignum_num_bytes(pub->e);
	if (exp_len > ASU_RSA_MAX_PUB_EXP_LEN)
		return TEE_ERROR_NOT_IMPLEMENTED;

	asu_rsa_bn2bin_pad(n_size, pub->n, n_bin);
	asu_rsa_bn2bin_pad(ASU_RSA_MAX_PUB_EXP_LEN, pub->e, e_bin);

	memset(key_comp, 0, sizeof(*key_comp));
	key_comp->key_size = n_size;

	memcpy(key_comp->modulus, n_bin, n_size);
	memcpy(&key_comp->pub_exp, e_bin, ASU_RSA_MAX_PUB_EXP_LEN);

	return TEE_SUCCESS;
}

/**
 * asu_rsa_pack_private_key() - Convert OP-TEE RSA private key to ASU payload
 * @priv: OP-TEE RSA private key-pair
 * @n_size: Modulus size in bytes
 * @key_comp: Output ASU private key structure
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result
asu_rsa_pack_private_key(struct rsa_keypair *priv, size_t n_size,
			 struct asu_rsa_pvt_key_comp *key_comp)
{
	uint8_t d_bin[ASU_RSA_MAX_MOD_LEN] = { };
	struct rsa_public_key pub = { };
	TEE_Result ret = TEE_SUCCESS;

	if (!priv || !key_comp)
		return TEE_ERROR_BAD_PARAMETERS;

	pub.e = priv->e;
	pub.n = priv->n;

	ret = asu_rsa_pack_public_key(&pub, n_size, &key_comp->pub_key);
	if (ret)
		goto OUT;

	asu_rsa_bn2bin_pad(n_size, priv->d, d_bin);
	memcpy(key_comp->pvt_exp, d_bin, n_size);
	key_comp->prime_comp_or_totient_present = 0U;

OUT:
	memzero_explicit(d_bin, sizeof(d_bin));

	return ret;
}

/**
 * asu_rsa_sha_validate_mode_and_type() - Validate ASU SHA type/mode tuple
 * @sha_type: ASU hash family selector
 * @sha_mode: ASU hash mode selector
 *
 * Return: TEE_SUCCESS when valid, TEE_ERROR_BAD_PARAMETERS otherwise.
 */
static TEE_Result asu_rsa_sha_validate_mode_and_type(uint8_t sha_type,
						     uint8_t sha_mode)
{
	if (sha_type != ASU_RSA_SHA2_TYPE && sha_type != ASU_RSA_SHA3_TYPE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (sha_mode == ASU_RSA_SHA_MODE_256 ||
	    sha_mode == ASU_RSA_SHA_MODE_384 ||
	    sha_mode == ASU_RSA_SHA_MODE_512)
		return TEE_SUCCESS;

	return TEE_ERROR_BAD_PARAMETERS;
}

/**
 * asu_rsa_validate_key_size() - Validate supported RSA key size
 * @key_size: Key size in bytes
 *
 * Return: TEE_SUCCESS when key size is supported, error otherwise.
 */
static TEE_Result asu_rsa_validate_key_size(uint32_t key_size)
{
	if (key_size == ASU_RSA_2048_KEY_SIZE ||
	    key_size == ASU_RSA_3072_KEY_SIZE ||
	    key_size == ASU_RSA_4096_KEY_SIZE)
		return TEE_SUCCESS;

	return TEE_ERROR_BAD_PARAMETERS;
}

/**
 * asu_rsa_validate_input_params() - Validate common RSA request fields
 * @req: RSA request payload
 *
 * Return: TEE_SUCCESS when valid, TEE_ERROR_BAD_PARAMETERS otherwise.
 */
static TEE_Result
asu_rsa_validate_input_params(struct asu_rsa_common_params *req,
			      bool allow_empty_input)
{
	if (!req || !req->input_data_addr || !req->key_comp_addr ||
	    asu_rsa_validate_key_size(req->key_size) ||
	    ((!allow_empty_input && !req->len) || req->len > req->key_size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (req->output_data_addr) {
		if (!req->output_data_len ||
		    req->output_data_len > req->key_size)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/**
 * asu_rsa_send_cmd() - Send command to ASUFW
 * @req: Command payload buffer
 * @req_size: Payload size in bytes
 * @module_id: ASU module identifier
 * @cmd_id: ASU command identifier
 * @resp_data: Array for fw response args and additional status (optional)
 * @fw_status: Returned fw status value on firmware failure (optional)
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result asu_rsa_send_cmd(void *req, uint32_t req_size,
				   uint8_t module_id,
				   uint8_t cmd_id,
				   uint32_t *resp_data,
				   uint32_t *fw_status)
{
	struct asu_client_params cparam = { };
	struct asu_rsa_resp_cbctx cbctx = { };
	uint8_t unique_id = ASU_UNIQUE_ID_MAX;
	uint8_t cmd_len_words = 0;
	uint32_t header = 0;
	uint32_t status = 0;
	TEE_Result ret = TEE_SUCCESS;
	bool uid_allocated = false;

	if (!req || !req_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (fw_status)
		*fw_status = 0U;

	/* Request size is multiple of ASU word size and fits in max length*/
	if ((req_size % ASU_RSA_WORD_LEN_IN_BYTES) != 0U ||
	    (req_size / ASU_RSA_WORD_LEN_IN_BYTES) > UINT8_MAX) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	cmd_len_words = (uint8_t)(req_size / ASU_RSA_WORD_LEN_IN_BYTES);

	cparam.priority = ASU_PRIORITY_HIGH;
	if (resp_data)
		memset(resp_data, 0,
		       sizeof(uint32_t) * ASU_RSA_RESP_ARRAY_WORDS);

	if (resp_data) {
		cbctx.resp_data = resp_data;
		cparam.cbptr = &cbctx;
		cparam.cbhandler = asu_rsa_resp_capture_cb;
	} else {
		cparam.cbptr = NULL;
		cparam.cbhandler = NULL;
	}

	unique_id = asu_alloc_unique_id();
	if (unique_id >= ASU_UNIQUE_ID_MAX) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}
	uid_allocated = true;

	header = asu_create_header(cmd_id, unique_id, module_id,
				   cmd_len_words);
	if (!header) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	ret = asu_update_queue_buffer_n_send_ipi(&cparam, req, req_size,
						 header, &status);

	if (ret) {
		if (module_id == ASU_MODULE_RSA_ID)
			EMSG("IPI send failed cmd=%" PRIu32 " ret=0x%x",
			     (uint32_t)cmd_id, ret);
		else
			EMSG("IPI send failed module=%" PRIu32 " cmd=%" PRIu32
			     " ret=0x%x", (uint32_t)module_id,
			     (uint32_t)cmd_id, ret);
		goto OUT;
	}

	if (status) {
		if (fw_status)
			*fw_status = status;

		if (module_id == ASU_MODULE_RSA_ID) {
			uint32_t fw_code = (uint32_t)status &
					   ASU_RSA_FW_STATUS_CODE_MASK;

			EMSG("Firmware failure cmd=%" PRIu32
				" status=0x%x fw_code=0x%03" PRIx32,
				(uint32_t)cmd_id, status, fw_code);
		}
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}

OUT:
	if (uid_allocated)
		asu_free_unique_id(unique_id);

	return ret;
}

/**
 * asu_rsa_size_bits_to_bytes() - Convert RSA key size from bits to bytes
 * @size_bits: Key size in bits
 * @size_bytes: Pointer to store key size in bytes
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result asu_rsa_size_bits_to_bytes(size_t size_bits,
					     size_t *size_bytes)
{
	if (!size_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (size_bits) {
	case (ASU_RSA_2048_KEY_SIZE * ASU_RSA_BITS_PER_BYTE):
		*size_bytes = ASU_RSA_2048_KEY_SIZE;
		return TEE_SUCCESS;
	case (ASU_RSA_3072_KEY_SIZE * ASU_RSA_BITS_PER_BYTE):
		*size_bytes = ASU_RSA_3072_KEY_SIZE;
		return TEE_SUCCESS;
	case (ASU_RSA_4096_KEY_SIZE * ASU_RSA_BITS_PER_BYTE):
		*size_bytes = ASU_RSA_4096_KEY_SIZE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/**
 * asu_rsa_pubexp_is_f4() - Check if RSA public exponent is F4 (0x10001)
 * @e: Pointer to the RSA public exponent
 *
 * Return: TEE_SUCCESS if exponent is F4, or error code on failure.
 */
static TEE_Result asu_rsa_pubexp_is_f4(struct bignum *e)
{
	uint8_t e_bin[ASU_RSA_MAX_PUB_EXP_LEN] = { };
	size_t e_len = 0;

	if (!e)
		return TEE_ERROR_BAD_PARAMETERS;

	e_len = crypto_bignum_num_bytes(e);
	if (!e_len)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (e_len > ASU_RSA_MAX_PUB_EXP_LEN)
		return TEE_ERROR_NOT_IMPLEMENTED;

	asu_rsa_bn2bin_pad(ASU_RSA_MAX_PUB_EXP_LEN, e, e_bin);
	if (e_bin[0] == 0x00U && e_bin[1] == 0x01U &&
	    e_bin[2] == 0x00U && e_bin[3] == 0x01U)
		return TEE_SUCCESS;

	return TEE_ERROR_NOT_IMPLEMENTED;
}

/**
 * asu_rsa_import_generated_keypair() - Import a generated RSA key-pair
 * @key: Pointer to the RSA key-pair structure
 * @size_bytes: Size of the key in bytes
 * @obj: Pointer to the ASU RSA key-pair object
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result
asu_rsa_import_generated_keypair(struct rsa_keypair *key,
				 size_t size_bytes,
				 uint8_t *obj)
{
	const uint8_t e_f4[] = { 0x01U, 0x00U, 0x01U };
	size_t prime_bytes = size_bytes / 2U;
	size_t keyobj_len = asu_rsa_keypair_blob_len(size_bytes);
	uint8_t *p = obj;
	TEE_Result ret = TEE_SUCCESS;

	if (!key || !obj || !size_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (keyobj_len > asu_rsa_keypair_blob_len(ASU_RSA_MAX_MOD_LEN))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = crypto_bignum_bin2bn(p, size_bytes, key->n);
	if (ret)
		return ret;
	p += size_bytes;

	ret = crypto_bignum_bin2bn(p, size_bytes, key->d);
	if (ret)
		return ret;
	p += size_bytes;

	ret = crypto_bignum_bin2bn(p, prime_bytes, key->p);
	if (ret)
		return ret;
	p += prime_bytes;

	ret = crypto_bignum_bin2bn(p, prime_bytes, key->q);
	if (ret)
		return ret;
	p += prime_bytes;

	ret = crypto_bignum_bin2bn(p, prime_bytes, key->dp);
	if (ret)
		return ret;
	p += prime_bytes;

	ret = crypto_bignum_bin2bn(p, prime_bytes, key->dq);
	if (ret)
		return ret;
	p += prime_bytes;

	ret = crypto_bignum_bin2bn(p, prime_bytes, key->qp);
	if (ret)
		return ret;

	ret = crypto_bignum_bin2bn(e_f4, sizeof(e_f4), key->e);

	return ret;
}

/**
 * asu_rsa_public_encrypt_cmd() - Issue raw RSA public encrypt command
 * @req: RSA command payload
 *
 * Return: TEE_SUCCESS on success, or error code.
 */
static TEE_Result asu_rsa_public_encrypt_cmd(struct asu_rsa_common_params *req)
{
	if (asu_rsa_validate_input_params(req, false) ||
	    !req->output_data_addr)
		return TEE_ERROR_BAD_PARAMETERS;

	return asu_rsa_send_cmd(req, sizeof(*req), ASU_MODULE_RSA_ID,
				ASU_RSA_PUBLIC_ENCRYPT_CMD_ID, NULL, NULL);
}

/**
 * asu_rsa_private_decrypt_cmd() - Issue raw RSA private decrypt command
 * @req: RSA command payload
 * @additional_status: Return additional status from firmware (optional)
 *
 * Return: TEE_SUCCESS on success, or error code.
 */
static TEE_Result
asu_rsa_private_decrypt_cmd(struct asu_rsa_common_params *req,
			    uint32_t *additional_status)
{
	uint32_t resp_data[ASU_RSA_RESP_ARRAY_WORDS] = { };
	TEE_Result ret = TEE_SUCCESS;

	if (asu_rsa_validate_input_params(req, false) ||
	    !req->output_data_addr || req->len != req->key_size)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = asu_rsa_send_cmd(req, sizeof(*req), ASU_MODULE_RSA_ID,
			       ASU_RSA_PRIVATE_DECRYPT_CMD_ID, resp_data,
			       NULL);
	if (!ret && additional_status)
		*additional_status =
			resp_data[ASU_RSA_RESP_ADDITIONAL_STATUS_IDX];

	return ret;
}

/**
 * asu_rsa_oaep_cmd() - Issue OAEP command to ASU firmware
 * @req: OAEP request payload
 * @is_decrypt: true for OAEP decrypt command, false for OAEP encrypt command
 * @actual_len: Actual output data length after decryption (decrypt only)
 * @additional_status: Returned additional status from firmware (optional)
 *
 * Return: TEE_SUCCESS on success or an error code.
 */
static TEE_Result
asu_rsa_oaep_cmd(struct asu_rsa_oaep_padding_params *req, bool is_decrypt,
		 uint32_t *actual_len, uint32_t *additional_status)
{
	uint8_t cmd_id = 0;
	uint32_t resp_data[ASU_RSA_RESP_ARRAY_WORDS] = { };
	TEE_Result ret = TEE_SUCCESS;

	if (!req || asu_rsa_validate_input_params(&req->rsa_op, !is_decrypt))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!req->rsa_op.output_data_addr || !req->optional_label_addr)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_decrypt && (!req->rsa_op.output_len_addr ||
			   req->rsa_op.len > req->rsa_op.key_size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (asu_rsa_sha_validate_mode_and_type(req->sha_type, req->sha_mode))
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_decrypt)
		cmd_id = (req->sha_type == ASU_RSA_SHA2_TYPE) ?
			ASU_RSA_OAEP_DEC_SHA2_CMD_ID :
			ASU_RSA_OAEP_DEC_SHA3_CMD_ID;
	else
		cmd_id = (req->sha_type == ASU_RSA_SHA2_TYPE) ?
			ASU_RSA_OAEP_ENC_SHA2_CMD_ID :
			ASU_RSA_OAEP_ENC_SHA3_CMD_ID;

	ret = asu_rsa_send_cmd(req, sizeof(*req), ASU_MODULE_RSA_ID,
			       cmd_id, resp_data, NULL);
	if (!ret) {
		if (actual_len)
			*actual_len = resp_data[ASU_RSA_RESP_DATA_WORD0_INDEX];
		if (additional_status)
			*additional_status =
				resp_data[ASU_RSA_RESP_ADDITIONAL_STATUS_IDX];
	}

	return ret;
}

/**
 * asu_rsa_oaep_encrypt_cmd() - Issue OAEP encrypt command to ASU firmware
 * @req: OAEP request payload
 *
 * Return: TEE_SUCCESS on success or an error code.
 */
static TEE_Result
asu_rsa_oaep_encrypt_cmd(struct asu_rsa_oaep_padding_params *req)
{
	return asu_rsa_oaep_cmd(req, false, NULL, NULL);
}

/**
 * asu_rsa_oaep_decrypt_cmd() - Issue OAEP decrypt command to ASU firmware
 * @req: OAEP request payload
 * @actual_len: Actual output length after decryption
 * @additional_status: Optional returned additional status from firmware
 *
 * Return: TEE_SUCCESS on success or an error code.
 */
static TEE_Result
asu_rsa_oaep_decrypt_cmd(struct asu_rsa_oaep_padding_params *req,
			 uint32_t *actual_len,
			 uint32_t *additional_status)
{
	return asu_rsa_oaep_cmd(req, true, actual_len, additional_status);
}

/**
 * asu_rsa_pss_sign_gen_cmd() - Issue PSS sign generation command
 * @req: PSS sign request payload
 *
 * Return: TEE_SUCCESS on success or an error code.
 */
static TEE_Result asu_rsa_pss_sign_gen_cmd(struct asu_rsa_padding_params *req)
{
	uint8_t cmd_id = 0;

	if (!req)
		return TEE_ERROR_BAD_PARAMETERS;

	if (asu_rsa_validate_input_params(&req->rsa_op, false)) {
		EMSG("Invalid RSA input params");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!req->rsa_op.output_data_addr) {
		EMSG("Missing output buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (req->rsa_op.len != TEE_SHA256_HASH_SIZE &&
	    req->rsa_op.len != TEE_SHA384_HASH_SIZE &&
	    req->rsa_op.len != TEE_SHA512_HASH_SIZE &&
	    req->input_data_type == ASU_RSA_HASHED_INPUT_DATA) {
		EMSG("Invalid hashed input length=%" PRIu32, req->rsa_op.len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (asu_rsa_sha_validate_mode_and_type(req->sha_type, req->sha_mode)) {
		EMSG("Invalid sha_type=%u sha_mode=%u",
		     req->sha_type, req->sha_mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cmd_id = (req->sha_type == ASU_RSA_SHA2_TYPE) ?
		ASU_RSA_PSS_SIGN_GEN_SHA2_CMD_ID :
		ASU_RSA_PSS_SIGN_GEN_SHA3_CMD_ID;

	return asu_rsa_send_cmd(req, sizeof(*req), ASU_MODULE_RSA_ID,
				cmd_id, NULL, NULL);
}

/**
 * asu_rsa_pss_sign_ver_cmd() - Issue PSS sign verification command
 * @req: PSS verify request payload
 *
 * Return: TEE_SUCCESS, TEE_ERROR_SIGNATURE_INVALID, or another error code.
 */
static TEE_Result asu_rsa_pss_sign_ver_cmd(struct asu_rsa_padding_params *req)
{
	uint8_t cmd_id = 0;
	uint32_t resp_data[ASU_RSA_RESP_ARRAY_WORDS] = { };
	uint32_t additional_status = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!req)
		return TEE_ERROR_BAD_PARAMETERS;

	if (asu_rsa_validate_input_params(&req->rsa_op, false)) {
		EMSG("Invalid RSA input params");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!req->signature_data_addr) {
		EMSG("Missing signature buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (req->rsa_op.len != TEE_SHA256_HASH_SIZE &&
	    req->rsa_op.len != TEE_SHA384_HASH_SIZE &&
	    req->rsa_op.len != TEE_SHA512_HASH_SIZE &&
	    req->input_data_type == ASU_RSA_HASHED_INPUT_DATA) {
		EMSG("Invalid hashed input length=%" PRIu32, req->rsa_op.len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (req->signature_len != req->rsa_op.key_size) {
		EMSG("Invalid signature length=%" PRIu32
		     " key_size=%" PRIu32,
		     req->signature_len, req->rsa_op.key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (asu_rsa_sha_validate_mode_and_type(req->sha_type, req->sha_mode)) {
		EMSG("Invalid sha_type=%u sha_mode=%u",
		     req->sha_type, req->sha_mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cmd_id = (req->sha_type == ASU_RSA_SHA2_TYPE) ?
		ASU_RSA_PSS_SIGN_VER_SHA2_CMD_ID :
		ASU_RSA_PSS_SIGN_VER_SHA3_CMD_ID;

	ret = asu_rsa_send_cmd(req, sizeof(*req), ASU_MODULE_RSA_ID,
			       cmd_id, resp_data, NULL);
	additional_status = resp_data[ASU_RSA_RESP_ADDITIONAL_STATUS_IDX];
	if (ret == TEE_ERROR_GENERIC &&
	    (additional_status == ASU_RSA_PSS_RIGHT_MOST_CMP_FAIL ||
	     additional_status == ASU_RSA_PSS_HASH_CMP_FAIL ||
	     additional_status == ASU_RSA_PSS_SIGN_VER_ERROR)) {
		EMSG("Signature mismatch status=0x%08" PRIx32,
		     additional_status);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	if (!ret && additional_status != ASU_RSA_PSS_SIGNATURE_VERIFIED) {
		EMSG("Signature verification fail status=0x%08" PRIx32,
		     additional_status);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		return ret;
	}

	return ret;
}

/**
 * asu_rsa_sw_rsaes_encrypt() - Software fallback for RSAES encrypt
 * @rsa_data: RSA encrypt operation context
 *
 * Return: TEE result code from software crypto backend.
 */
static TEE_Result asu_rsa_sw_rsaes_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	return sw_crypto_acipher_rsaes_encrypt(rsa_data->algo,
			rsa_data->key.key, rsa_data->label.data,
			rsa_data->label.length, rsa_data->mgf_algo,
			rsa_data->message.data, rsa_data->message.length,
			rsa_data->cipher.data, &rsa_data->cipher.length);
}

/**
 * asu_rsa_sw_rsanopad_encrypt() - Software fallback for RSA NOPAD encrypt
 * @rsa_data: RSA encrypt operation context
 *
 * Return: TEE result code from software crypto backend.
 */
static TEE_Result asu_rsa_sw_rsanopad_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	return sw_crypto_acipher_rsanopad_encrypt(rsa_data->key.key,
			rsa_data->message.data, rsa_data->message.length,
			rsa_data->cipher.data, &rsa_data->cipher.length);
}

/**
 * asu_rsa_sw_rsaes_decrypt() - Software fallback for RSAES decrypt
 * @rsa_data: RSA decrypt operation context
 *
 * Return: TEE result code from software crypto backend.
 */
static TEE_Result asu_rsa_sw_rsaes_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	return sw_crypto_acipher_rsaes_decrypt(rsa_data->algo,
			rsa_data->key.key, rsa_data->label.data,
			rsa_data->label.length, rsa_data->mgf_algo,
			rsa_data->cipher.data, rsa_data->cipher.length,
			rsa_data->message.data, &rsa_data->message.length);
}

/**
 * asu_rsa_sw_rsanopad_decrypt() - Software fallback for RSA NOPAD decrypt
 * @rsa_data: RSA decrypt operation context
 *
 * Return: TEE result code from software crypto backend.
 */
static TEE_Result asu_rsa_sw_rsanopad_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	return sw_crypto_acipher_rsanopad_decrypt(rsa_data->key.key,
			rsa_data->cipher.data, rsa_data->cipher.length,
			rsa_data->message.data, &rsa_data->message.length);
}

/**
 * asu_rsa_sw_rsassa_sign() - Software fallback for RSASSA sign
 * @ssa_data: RSASSA sign operation context
 *
 * Return: TEE result code from software crypto backend.
 */
static TEE_Result asu_rsa_sw_rsassa_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	return sw_crypto_acipher_rsassa_sign(ssa_data->algo,
			ssa_data->key.key, ssa_data->salt_len,
			ssa_data->message.data, ssa_data->message.length,
			ssa_data->signature.data, &ssa_data->signature.length);
}

/**
 * asu_rsa_sw_rsassa_verify() - Software fallback for RSASSA verify
 * @ssa_data: RSASSA verify operation context
 *
 * Return: TEE result code from software crypto backend.
 */
static TEE_Result asu_rsa_sw_rsassa_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	return sw_crypto_acipher_rsassa_verify(ssa_data->algo,
			ssa_data->key.key, ssa_data->salt_len,
			ssa_data->message.data, ssa_data->message.length,
			ssa_data->signature.data, ssa_data->signature.length);
}

/**
 * asu_rsa_prepare_input_buf() - Allocate and prepare input buffer for
 * ASU command
 * @src: Source input data
 * @len: Length of input data in bytes
 * @buf: Returns allocated buffer address
 * @alloc_len: Returns allocated buffer length in bytes (aligned)
 * @alloc_err: Error message to log on allocation failure
 *
 * Return: TEE_SUCCESS on success, or TEE_ERROR_OUT_OF_MEMORY on failure.
 */
static TEE_Result asu_rsa_prepare_input_buf(const uint8_t *src, size_t len,
					    uint8_t **buf, size_t *alloc_len,
					    const char *alloc_err)
{
	size_t alloc_size = len ? len : 1U;

	if (!buf || (len && !src))
		return TEE_ERROR_BAD_PARAMETERS;

	*buf = asu_rsa_alloc_align_buf(alloc_size, alloc_len);
	if (!*buf) {
		EMSG("%s", alloc_err);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (len)
		memcpy(*buf, src, len);

	cache_operation(TEE_CACHEFLUSH, *buf, *alloc_len);

	return TEE_SUCCESS;
}

/**
 * asu_rsa_prepare_output_buf() - Allocate and prepare output buffer for
 * ASU command
 * @len: Expected length of output data in bytes
 * @buf: Returns allocated buffer address
 * @alloc_len: Returns allocated buffer length in bytes (aligned)
 * @alloc_err: Error message to log on allocation failure
 *
 * Return: TEE_SUCCESS on success, or TEE_ERROR_OUT_OF_MEMORY on failure.
 */
static TEE_Result asu_rsa_prepare_output_buf(size_t len, uint8_t **buf,
					     size_t *alloc_len,
					     const char *alloc_err)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	*buf = asu_rsa_alloc_align_buf(len, alloc_len);
	if (!*buf) {
		EMSG("%s", alloc_err);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	cache_operation(TEE_CACHEFLUSH, *buf, *alloc_len);

	return TEE_SUCCESS;
}

/**
 * asu_rsa_prepare_oaep_label_buf() - Allocate and prepare OAEP label buffer
 * @label_data: OAEP label source data
 * @label_len: OAEP label length in bytes
 * @label_buf: Returns allocated label buffer address
 * @label_alloc_len: Returns allocated label buffer length (aligned)
 *
 * Return: TEE_SUCCESS on success, or error code.
 */
static TEE_Result asu_rsa_prepare_oaep_label_buf(const uint8_t *label_data,
						 size_t label_len,
						 uint8_t **label_buf,
						 size_t *label_alloc_len)
{
	size_t alloc_size = label_len ? label_len : 1U;

	if (!label_buf || (label_len && !label_data))
		return TEE_ERROR_BAD_PARAMETERS;

	*label_buf = asu_rsa_alloc_align_buf(alloc_size, label_alloc_len);
	if (!*label_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (label_len)
		memcpy(*label_buf, label_data, label_len);

	cache_operation(TEE_CACHEFLUSH, *label_buf, *label_alloc_len);

	return TEE_SUCCESS;
}

/**
 * asu_rsa_fill_request() - Populate common RSA request fields for ASU firmware
 * @req: RSA request payload to populate
 * @input_addr: Physical address of input data buffer
 * @output_addr: Physical address of output data buffer
 * @key_addr: Physical address of key component buffer
 * @len: Length of input data in bytes
 * @output_len: Length of output buffer in bytes
 * @key_size: RSA key size in bytes
 * @key_id: Key identifier for ASU firmware (if applicable)
 *
 * Return: None.
 */
static void asu_rsa_fill_request(struct asu_rsa_common_params *req,
				 uint64_t input_addr, uint64_t output_addr,
				 uint64_t key_addr, uint32_t len,
				 uint32_t output_len, uint32_t key_size,
				 uint32_t key_id)
{
	req->input_data_addr = input_addr;
	req->output_data_addr = output_addr;
	req->expo_comp_addr = 0;
	req->key_comp_addr = key_addr;
	req->output_len_addr = 0;
	req->len = len;
	req->output_data_len = output_len;
	req->key_size = key_size;
	req->key_id = key_id;
}

/**
 * asu_rsa_encrypt() - drvcrypt RSA encrypt callback
 * @rsa_data: Operation context carrying key/input/output/padding metadata
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result asu_rsa_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	struct asu_rsa_common_params req = { };
	struct asu_rsa_oaep_padding_params oaep_req = { };
	struct asu_rsa_pub_key_comp *key_comp = NULL;
	uint8_t *msg_buf = NULL;
	uint8_t *out_buf = NULL;
	uint8_t *label_buf = NULL;
	size_t key_comp_alloc_len = 0;
	size_t msg_alloc_len = 0;
	size_t out_alloc_len = 0;
	size_t label_alloc_len = 0;
	size_t label_len = 0;
	bool use_oaep = false;
	uint8_t sha_type = 0;
	uint8_t sha_mode = 0;
	uint32_t expected_mgf_algo = 0;
	uint32_t key_size = 0;
	uint32_t input_len = 0;
	uint32_t output_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!rsa_data || !rsa_data->key.key) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_PKCS_V1_5:
		ret = asu_rsa_sw_rsaes_encrypt(rsa_data);
		goto OUT;
	case DRVCRYPT_RSA_OAEP:
		expected_mgf_algo = TEE_INTERNAL_HASH_TO_ALGO(rsa_data->algo);
		if (rsa_data->mgf_algo &&
		    rsa_data->mgf_algo != expected_mgf_algo) {
			ret = asu_rsa_sw_rsaes_encrypt(rsa_data);
			goto OUT;
		}
		/*
		 * ASU supports only a subset of OAEP hash variants.
		 * Fallback to software for unsupported OAEP algorithms
		 * (for example SHA1/SHA224).
		 */
		ret = asu_rsa_sha_cfg_from_oaep_algo(rsa_data->algo,
						     &sha_type, &sha_mode);
		if (ret) {
			ret = asu_rsa_sw_rsaes_encrypt(rsa_data);
			goto OUT;
		}
		if (asu_rsa_validate_key_size(rsa_data->key.n_size)) {
			ret = asu_rsa_sw_rsaes_encrypt(rsa_data);
			goto OUT;
		}
		use_oaep = true;
		break;
	case DRVCRYPT_RSA_NOPAD:
		if (rsa_data->message.length > rsa_data->key.n_size) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto OUT;
		}

		if (asu_rsa_validate_key_size(rsa_data->key.n_size)) {
			ret = asu_rsa_sw_rsanopad_encrypt(rsa_data);
			goto OUT;
		}

		break;
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
		if (rsa_data->message.length > rsa_data->key.n_size) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto OUT;
		}
		ret = asu_rsa_sw_rsanopad_encrypt(rsa_data);
		goto OUT;
	default:
		EMSG("Unsupported rsa_id=%" PRIu32, (uint32_t)rsa_data->rsa_id);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		goto OUT;
	}

	if (rsa_data->cipher.length < rsa_data->key.n_size) {
		rsa_data->cipher.length = rsa_data->key.n_size;
		EMSG("Short output buffer");
		ret = TEE_ERROR_SHORT_BUFFER;
		goto OUT;
	}

	key_comp = asu_rsa_alloc_align_buf(sizeof(*key_comp),
					   &key_comp_alloc_len);
	if (!key_comp) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}

	ret = asu_rsa_pack_public_key(rsa_data->key.key, rsa_data->key.n_size,
				      key_comp);
	if (ret) {
		EMSG("Public key pack failed ret=0x%x", ret);
		goto OUT;
	}

	ret = asu_rsa_prepare_input_buf(rsa_data->message.data,
					rsa_data->message.length,
					&msg_buf, &msg_alloc_len,
					"Message buffer allocation failed");
	if (ret)
		goto OUT;

	ret = asu_rsa_prepare_output_buf(rsa_data->key.n_size, &out_buf,
					 &out_alloc_len,
					 "Output buffer allocation failed");
	if (ret)
		goto OUT;

	cache_operation(TEE_CACHEFLUSH, key_comp, key_comp_alloc_len);
	key_size = (uint32_t)rsa_data->key.n_size;
	input_len = (uint32_t)rsa_data->message.length;
	output_len = (uint32_t)rsa_data->key.n_size;

	asu_rsa_fill_request(&req, virt_to_phys(msg_buf),
			     virt_to_phys(out_buf), virt_to_phys(key_comp),
			     input_len, output_len, key_size, 0);

	if (use_oaep) {
		label_len = rsa_data->label.length;

		ret = asu_rsa_prepare_oaep_label_buf(rsa_data->label.data,
						     label_len, &label_buf,
						     &label_alloc_len);
		if (ret)
			goto OUT;

		oaep_req.rsa_op = req;
		oaep_req.optional_label_addr = virt_to_phys(label_buf);
		oaep_req.optional_label_size = label_len;
		oaep_req.sha_type = sha_type;
		oaep_req.sha_mode = sha_mode;

		ret = asu_rsa_oaep_encrypt_cmd(&oaep_req);
	} else {
		ret = asu_rsa_public_encrypt_cmd(&req);
	}

	if (ret) {
		EMSG("Command failed ret=0x%x", ret);
		goto OUT;
	}

	cache_operation(TEE_CACHEINVALIDATE, out_buf, rsa_data->key.n_size);
	rsa_data->cipher.length = rsa_data->key.n_size;
	memcpy(rsa_data->cipher.data, out_buf, rsa_data->cipher.length);

	DMSG("RSA encryption successful");

OUT:
	if (msg_buf)
		memzero_explicit(msg_buf, msg_alloc_len);
	if (out_buf)
		memzero_explicit(out_buf, out_alloc_len);
	if (label_buf)
		memzero_explicit(label_buf, label_alloc_len);
	if (key_comp)
		memzero_explicit(key_comp, key_comp_alloc_len);
	free(msg_buf);
	free(out_buf);
	free(label_buf);
	free(key_comp);

	return ret;
}

/**
 * asu_rsa_decrypt() - drvcrypt RSA decrypt callback
 * @rsa_data: Operation context carrying key/input/output/padding metadata
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result asu_rsa_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	struct asu_rsa_common_params req = { };
	struct asu_rsa_oaep_padding_params oaep_req = { };
	struct asu_rsa_pvt_key_comp *key_comp = NULL;
	uint8_t *cipher_buf = NULL;
	uint8_t *out_buf = NULL;
	uint8_t *label_buf = NULL;
	uint32_t *fw_output_len_buf = NULL;
	size_t key_comp_alloc_len = 0;
	size_t cipher_alloc_len = 0;
	size_t out_alloc_len = 0;
	size_t label_alloc_len = 0;
	size_t fw_out_len_alloc = 0;
	size_t label_len = 0;
	bool use_oaep = false;
	uint8_t sha_type = 0;
	uint8_t sha_mode = 0;
	uint32_t expected_mgf_algo = 0;
	uint32_t additional_status = 0;
	uint32_t actual_oaep_len = 0;
	uint32_t key_size = 0;
	uint32_t input_len = 0;
	uint32_t output_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!rsa_data || !rsa_data->key.key) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_PKCS_V1_5:
		ret = asu_rsa_sw_rsaes_decrypt(rsa_data);
		goto OUT;
	case DRVCRYPT_RSA_OAEP:
		expected_mgf_algo = TEE_INTERNAL_HASH_TO_ALGO(rsa_data->algo);
		if (rsa_data->mgf_algo &&
		    rsa_data->mgf_algo != expected_mgf_algo) {
			ret = asu_rsa_sw_rsaes_decrypt(rsa_data);
			goto OUT;
		}
		/*
		 * ASU supports only a subset of OAEP hash variants.
		 * Fallback to software for unsupported OAEP algorithms
		 * (for example SHA1/SHA224).
		 */
		ret = asu_rsa_sha_cfg_from_oaep_algo(rsa_data->algo,
						     &sha_type, &sha_mode);
		if (ret) {
			ret = asu_rsa_sw_rsaes_decrypt(rsa_data);
			goto OUT;
		}
		/* OAEP decryption input length must not exceed key_size */
		if (rsa_data->cipher.length > rsa_data->key.n_size) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto OUT;
		}
		if (asu_rsa_validate_key_size(rsa_data->key.n_size)) {
			ret = asu_rsa_sw_rsaes_decrypt(rsa_data);
			goto OUT;
		}
		use_oaep = true;
		break;
	case DRVCRYPT_RSA_NOPAD:
		if (rsa_data->cipher.length > rsa_data->key.n_size) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto OUT;
		}

		if (asu_rsa_validate_key_size(rsa_data->key.n_size) ||
		    rsa_data->cipher.length != rsa_data->key.n_size) {
			ret = asu_rsa_sw_rsanopad_decrypt(rsa_data);
			goto OUT;
		}
		break;
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
		if (rsa_data->cipher.length > rsa_data->key.n_size) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto OUT;
		}
		ret = asu_rsa_sw_rsanopad_decrypt(rsa_data);
		goto OUT;
	default:
		EMSG("Unsupported rsa_id=%" PRIu32, (uint32_t)rsa_data->rsa_id);
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto OUT;
	}

	key_comp = asu_rsa_alloc_align_buf(sizeof(*key_comp),
					   &key_comp_alloc_len);
	if (!key_comp) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}

	ret = asu_rsa_pack_private_key(rsa_data->key.key, rsa_data->key.n_size,
				       key_comp);
	if (ret) {
		EMSG("Private key pack failed ret=0x%x", ret);
		goto OUT;
	}

	ret = asu_rsa_prepare_input_buf(rsa_data->cipher.data,
					rsa_data->cipher.length,
					&cipher_buf, &cipher_alloc_len,
					"Cipher buffer allocation failed");
	if (ret)
		goto OUT;

	ret = asu_rsa_prepare_output_buf(rsa_data->key.n_size, &out_buf,
					 &out_alloc_len,
					 "Output buffer allocation failed");
	if (ret)
		goto OUT;

	cache_operation(TEE_CACHEFLUSH, key_comp, key_comp_alloc_len);
	key_size = (uint32_t)rsa_data->key.n_size;
	input_len = (uint32_t)rsa_data->cipher.length;
	output_len = (uint32_t)rsa_data->key.n_size;

	asu_rsa_fill_request(&req, virt_to_phys(cipher_buf),
			     virt_to_phys(out_buf), virt_to_phys(key_comp),
			     input_len, output_len, key_size, 0);

	if (use_oaep) {
		label_len = rsa_data->label.length;

		fw_output_len_buf = asu_rsa_alloc_align_buf(sizeof(uint32_t),
							    &fw_out_len_alloc);
		if (!fw_output_len_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto OUT;
		}

		*fw_output_len_buf = 0U;
		cache_operation(TEE_CACHEFLUSH, fw_output_len_buf,
				fw_out_len_alloc);

		ret = asu_rsa_prepare_oaep_label_buf(rsa_data->label.data,
						     label_len, &label_buf,
						     &label_alloc_len);
		if (ret)
			goto OUT;

		oaep_req.rsa_op = req;
		oaep_req.rsa_op.output_len_addr =
			virt_to_phys(fw_output_len_buf);
		oaep_req.optional_label_addr = virt_to_phys(label_buf);
		oaep_req.optional_label_size = label_len;
		oaep_req.sha_type = sha_type;
		oaep_req.sha_mode = sha_mode;

		ret = asu_rsa_oaep_decrypt_cmd(&oaep_req, &actual_oaep_len,
					       &additional_status);

		cache_operation(TEE_CACHEINVALIDATE, fw_output_len_buf,
				fw_out_len_alloc);
	} else {
		ret = asu_rsa_private_decrypt_cmd(&req, &additional_status);
	}

	if (ret) {
		EMSG("ASU operation failed ret=0x%x", ret);
		goto OUT;
	}

	if (!use_oaep && additional_status != ASU_RSA_DECRYPTION_SUCCESS) {
		EMSG("Decrypt additional status=0x%08" PRIx32,
		     additional_status);
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}

	cache_operation(TEE_CACHEINVALIDATE, out_buf, rsa_data->key.n_size);

	if (rsa_data->rsa_id == DRVCRYPT_RSA_OAEP) {
		/* ASU FW reports OAEP output length in response word0. */
		size_t actual_len = actual_oaep_len;

		if (!actual_len && fw_output_len_buf)
			actual_len = *fw_output_len_buf;

		if (actual_len > rsa_data->key.n_size) {
			EMSG("Invalid OAEP output length=%zu key=%zu",
			     actual_len, rsa_data->key.n_size);
			ret = TEE_ERROR_GENERIC;
			goto OUT;
		}

		if (rsa_data->message.length < actual_len) {
			rsa_data->message.length = actual_len;
			ret = TEE_ERROR_SHORT_BUFFER;
			goto OUT;
		}

		rsa_data->message.length = actual_len;
		memcpy(rsa_data->message.data, out_buf, actual_len);
	} else if (rsa_data->rsa_id == DRVCRYPT_RSA_NOPAD) {
		size_t offset = 0;
		size_t out_len = rsa_data->key.n_size;

		while ((offset < out_len - 1) && (out_buf[offset] == 0))
			offset++;

		out_len -= offset;
		if (rsa_data->message.length < out_len) {
			rsa_data->message.length = out_len;
			ret = TEE_ERROR_SHORT_BUFFER;
			goto OUT;
		}

		rsa_data->message.length = out_len;
		memcpy(rsa_data->message.data, out_buf + offset, out_len);
	} else {
		if (rsa_data->message.length < rsa_data->key.n_size) {
			rsa_data->message.length = rsa_data->key.n_size;
			ret = TEE_ERROR_SHORT_BUFFER;
			goto OUT;
		}

		rsa_data->message.length = rsa_data->key.n_size;
		memcpy(rsa_data->message.data, out_buf, rsa_data->key.n_size);
	}

	DMSG("RSA decryption successful");

OUT:
	if (cipher_buf)
		memzero_explicit(cipher_buf, cipher_alloc_len);
	if (out_buf)
		memzero_explicit(out_buf, out_alloc_len);
	if (label_buf)
		memzero_explicit(label_buf, label_alloc_len);
	if (fw_output_len_buf)
		memzero_explicit(fw_output_len_buf, fw_out_len_alloc);
	if (key_comp)
		memzero_explicit(key_comp, key_comp_alloc_len);
	free(cipher_buf);
	free(out_buf);
	free(label_buf);
	free(fw_output_len_buf);
	free(key_comp);

	return ret;
}

/**
 * asu_rsa_ssa_sign() - drvcrypt RSASSA sign callback
 * @ssa_data: Sign context containing algorithm, key, hash, and buffers
 *
 * Return: TEE_SUCCESS on success, or error code on failure.
 */
static TEE_Result asu_rsa_ssa_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	uint8_t sha_type = 0;
	uint8_t sha_mode = 0;
	struct asu_rsa_padding_params req = { };
	struct asu_rsa_pvt_key_comp *key_comp = NULL;
	uint8_t *msg_buf = NULL;
	uint8_t *sig_buf = NULL;
	size_t key_comp_alloc_len = 0;
	size_t msg_alloc_len = 0;
	size_t sig_alloc_len = 0;
	uint32_t key_size = 0;
	uint32_t input_len = 0;
	uint32_t output_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!ssa_data || !ssa_data->key.key) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_512:
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_224:
		ret = asu_rsa_sw_rsassa_sign(ssa_data);
		goto OUT;
	default:
		EMSG("Unsupported algo=0x%" PRIx32, ssa_data->algo);
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto OUT;
	}

	if (asu_rsa_validate_key_size(ssa_data->key.n_size)) {
		ret = asu_rsa_sw_rsassa_sign(ssa_data);
		goto OUT;
	}

	if (ssa_data->signature.length < ssa_data->key.n_size) {
		ssa_data->signature.length = ssa_data->key.n_size;
		EMSG("Short signature output buffer");
		ret = TEE_ERROR_SHORT_BUFFER;
		goto OUT;
	}

	key_comp = asu_rsa_alloc_align_buf(sizeof(*key_comp),
					   &key_comp_alloc_len);
	if (!key_comp) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}

	ret = asu_rsa_sha_cfg_from_hash_algo(ssa_data->hash_algo,
					     &sha_type, &sha_mode);
	if (ret) {
		EMSG("Hash cfg failed ret=0x%x, hash algo=0x%" PRIx32,
		     ret, ssa_data->hash_algo);
		goto OUT;
	}
	ret = asu_rsa_pack_private_key(ssa_data->key.key, ssa_data->key.n_size,
				       key_comp);
	if (ret) {
		EMSG("Private key pack failed ret=0x%x", ret);
		goto OUT;
	}

	ret = asu_rsa_prepare_input_buf(ssa_data->message.data,
					ssa_data->message.length,
					&msg_buf, &msg_alloc_len,
					"Message buffer allocation failed");
	if (ret)
		goto OUT;

	ret = asu_rsa_prepare_output_buf(ssa_data->key.n_size, &sig_buf,
					 &sig_alloc_len,
					 "Signature buffer allocation failed");
	if (ret)
		goto OUT;

	cache_operation(TEE_CACHEFLUSH, key_comp, key_comp_alloc_len);
	key_size = (uint32_t)ssa_data->key.n_size;
	input_len = (uint32_t)ssa_data->message.length;
	output_len = (uint32_t)ssa_data->key.n_size;

	asu_rsa_fill_request(&req.rsa_op, virt_to_phys(msg_buf),
			     virt_to_phys(sig_buf), virt_to_phys(key_comp),
			     input_len, output_len, key_size, 0);

	req.salt_len = ssa_data->salt_len;
	req.sha_type = sha_type;
	req.sha_mode = sha_mode;
	req.input_data_type = ASU_RSA_HASHED_INPUT_DATA;

	ret = asu_rsa_pss_sign_gen_cmd(&req);
	if (ret) {
		EMSG("ASU command failed ret=0x%x", ret);
		goto OUT;
	}

	cache_operation(TEE_CACHEINVALIDATE, sig_buf, ssa_data->key.n_size);
	ssa_data->signature.length = ssa_data->key.n_size;
	memcpy(ssa_data->signature.data, sig_buf, ssa_data->key.n_size);

	DMSG("RSA signing successful");

OUT:
	if (msg_buf)
		memzero_explicit(msg_buf, msg_alloc_len);
	if (sig_buf)
		memzero_explicit(sig_buf, sig_alloc_len);
	if (key_comp)
		memzero_explicit(key_comp, key_comp_alloc_len);
	free(msg_buf);
	free(sig_buf);
	free(key_comp);

	return ret;
}

/**
 * asu_rsa_ssa_verify() - drvcrypt RSASSA verify callback
 * @ssa_data: Verify context containing algorithm, key, hash, and signature
 *
 * Return: TEE_SUCCESS on successful verification, TEE_ERROR_SIGNATURE_INVALID
 *	if signature does not match, or other error code on failure.
 */
static TEE_Result asu_rsa_ssa_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	uint8_t sha_type = 0;
	uint8_t sha_mode = 0;
	struct asu_rsa_padding_params req = { };
	struct asu_rsa_pub_key_comp *key_comp = NULL;
	uint8_t *msg_buf = NULL;
	uint8_t *sig_buf = NULL;
	size_t key_comp_alloc_len = 0;
	size_t msg_alloc_len = 0;
	size_t sig_alloc_len = 0;
	uint32_t key_size = 0;
	uint32_t input_len = 0;
	uint32_t output_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!ssa_data || !ssa_data->key.key) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_512:
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_224:
		ret = asu_rsa_sw_rsassa_verify(ssa_data);
		goto OUT;
	default:
		EMSG("Unsupported algo=0x%" PRIx32, ssa_data->algo);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		goto OUT;
	}

	if (asu_rsa_validate_key_size(ssa_data->key.n_size)) {
		ret = asu_rsa_sw_rsassa_verify(ssa_data);
		goto OUT;
	}

	key_comp = asu_rsa_alloc_align_buf(sizeof(*key_comp),
					   &key_comp_alloc_len);
	if (!key_comp) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}

	ret = asu_rsa_sha_cfg_from_hash_algo(ssa_data->hash_algo,
					     &sha_type, &sha_mode);
	if (ret) {
		EMSG("Hash cfg failed ret=0x%x, hash algo=0x%" PRIx32,
		     ret, ssa_data->hash_algo);
		goto OUT;
	}
	ret = asu_rsa_pack_public_key(ssa_data->key.key, ssa_data->key.n_size,
				      key_comp);
	if (ret) {
		EMSG("Public key pack failed ret=0x%x", ret);
		goto OUT;
	}

	ret = asu_rsa_prepare_input_buf(ssa_data->message.data,
					ssa_data->message.length,
					&msg_buf, &msg_alloc_len,
					"Message buffer allocation failed");
	if (ret)
		goto OUT;

	ret = asu_rsa_prepare_input_buf(ssa_data->signature.data,
					ssa_data->signature.length,
					&sig_buf, &sig_alloc_len,
					"Signature buffer allocation failed");
	if (ret)
		goto OUT;

	cache_operation(TEE_CACHEFLUSH, key_comp, key_comp_alloc_len);
	key_size = (uint32_t)ssa_data->key.n_size;
	input_len = (uint32_t)ssa_data->message.length;
	output_len = 0;

	asu_rsa_fill_request(&req.rsa_op, virt_to_phys(msg_buf), 0,
			     virt_to_phys(key_comp),
			     input_len, output_len, key_size, 0);

	req.signature_data_addr = virt_to_phys(sig_buf);
	req.signature_len = ssa_data->signature.length;
	req.salt_len = ssa_data->salt_len;
	req.sha_type = sha_type;
	req.sha_mode = sha_mode;
	req.input_data_type = ASU_RSA_HASHED_INPUT_DATA;

	ret = asu_rsa_pss_sign_ver_cmd(&req);
	if (ret)
		EMSG("ASU command failed ret=0x%x", ret);
	else
		DMSG("RSA signature verification successful");

OUT:
	if (msg_buf)
		memzero_explicit(msg_buf, msg_alloc_len);
	if (sig_buf)
		memzero_explicit(sig_buf, sig_alloc_len);
	if (key_comp)
		memzero_explicit(key_comp, key_comp_alloc_len);
	free(msg_buf);
	free(sig_buf);
	free(key_comp);

	return ret;
}

/**
 * asu_rsa_gen_keypair() - Generate RSA key-pair
 * @key: RSA key-pair structure
 * @size_bits: Key size in bits
 *
 * Attempt RSA key generation in ASU hardware through KeyManager and import
 * generated key components into OP-TEE bignums. Falls back to software when
 * hardware key generation is unavailable for this request.
 *
 * Return: TEE result code.
 */
static TEE_Result asu_rsa_gen_keypair(struct rsa_keypair *key,
				      size_t size_bits)
{
	struct asu_rsa_km_params req = { };
	uint8_t *key_obj = NULL;
	size_t key_obj_alloc_len = 0;
	size_t key_obj_req_len = 0;
	size_t size_bytes = 0;
	uint32_t fw_status = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	if (asu_rsa_size_bits_to_bytes(size_bits, &size_bytes) ||
	    asu_rsa_pubexp_is_f4(key->e))
		return sw_crypto_acipher_gen_rsa_key(key, size_bits);

	key_obj_req_len = asu_rsa_keypair_blob_len(size_bytes);
	key_obj = asu_rsa_alloc_align_buf(key_obj_req_len, &key_obj_alloc_len);
	if (!key_obj)
		return TEE_ERROR_OUT_OF_MEMORY;

	req.key_metadata.length = (uint16_t)size_bytes;
	req.key_metadata.key_id = 0U;
	req.key_metadata.key_type = ASU_RSA_KM_KEY_TYPE_RSA_PVT;
	req.key_metadata.vault_id = ASU_RSA_KM_VAULT_ID;
	req.key_metadata.key_attributes = 0U;
	req.key_metadata.key_use_case = ASU_RSA_KM_KEY_USE_CASE_ALL;
	req.key_metadata.epoch_time = 0U;
	req.key_metadata.usage_count =
		ASU_RSA_KM_USAGE_COUNT_NON_DEPLETING;
	req.wrapped_input_len = 0U;
	req.key_object_addr = virt_to_phys(key_obj);
	req.key_id_addr = 0U;

	cache_operation(TEE_CACHEFLUSH, key_obj, key_obj_alloc_len);
	cache_operation(TEE_CACHEFLUSH, &req, sizeof(req));

	ret = asu_rsa_send_cmd(&req, sizeof(req),
			       ASU_MODULE_KEYMANAGER_ID,
			       ASU_KM_GEN_RSA_KEY_PAIR_CMD_ID,
			       NULL, &fw_status);
	if (ret) {
		DMSG("HW key-pair unavailable status=0x%08" PRIx32
		     ", using SW fallback", fw_status);
		ret = sw_crypto_acipher_gen_rsa_key(key, size_bits);
		goto OUT;
	}

	cache_operation(TEE_CACHEINVALIDATE, key_obj, key_obj_alloc_len);

	ret = asu_rsa_import_generated_keypair(key, size_bytes, key_obj);
	if (ret) {
		EMSG("Failed to import RSA key material ret=0x%x", ret);
		goto OUT;
	}
	DMSG("RSA key-pair import successful (size=%zu bits)", size_bits);

OUT:
	if (key_obj)
		memzero_explicit(key_obj, key_obj_alloc_len);
	free(key_obj);

	return ret;
}

/**
 * asu_rsa_bn_alloc_max() - Allocate bignum with max RSA bit-size capacity
 * @s: Returned bignum pointer
 *
 * Return: true on success, false otherwise.
 */
static bool asu_rsa_bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(ASU_RSA_MAX_KEY_SIZE_BITS);

	return *s;
}

/**
 * asu_rsa_alloc_keypair() - Allocate RSA key-pair bignum fields
 * @s: RSA key-pair destination
 * @key_size_bits: Unused key size hint
 *
 * Return: TEE_SUCCESS or TEE_ERROR_OUT_OF_MEMORY.
 */
static TEE_Result asu_rsa_alloc_keypair(struct rsa_keypair *s,
					size_t key_size_bits __unused)
{
	TEE_Result ret = TEE_SUCCESS;

	memset(s, 0, sizeof(*s));
	if (!asu_rsa_bn_alloc_max(&s->e)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}
	if (!asu_rsa_bn_alloc_max(&s->d))
		goto ERR;
	if (!asu_rsa_bn_alloc_max(&s->n))
		goto ERR;
	if (!asu_rsa_bn_alloc_max(&s->p))
		goto ERR;
	if (!asu_rsa_bn_alloc_max(&s->q))
		goto ERR;
	if (!asu_rsa_bn_alloc_max(&s->qp))
		goto ERR;
	if (!asu_rsa_bn_alloc_max(&s->dp))
		goto ERR;
	if (!asu_rsa_bn_alloc_max(&s->dq))
		goto ERR;

	goto OUT;

ERR:
	ret = TEE_ERROR_OUT_OF_MEMORY;
	crypto_bignum_free(&s->e);
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->n);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->q);
	crypto_bignum_free(&s->qp);
	crypto_bignum_free(&s->dp);
	crypto_bignum_free(&s->dq);

OUT:

	return ret;
}

/**
 * asu_rsa_alloc_publickey() - Allocate RSA public key bignum fields
 * @s: RSA public key destination
 * @key_size_bits: Unused key size hint
 *
 * Return: TEE_SUCCESS or TEE_ERROR_OUT_OF_MEMORY.
 */
static TEE_Result asu_rsa_alloc_publickey(struct rsa_public_key *s,
					  size_t key_size_bits __unused)
{
	TEE_Result ret = TEE_SUCCESS;

	memset(s, 0, sizeof(*s));
	if (!asu_rsa_bn_alloc_max(&s->e)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}
	if (!asu_rsa_bn_alloc_max(&s->n)) {
		crypto_bignum_free(&s->e);
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto OUT;
	}

OUT:

	return ret;
}

/**
 * asu_rsa_free_publickey() - Free RSA public key bignum fields
 * @s: RSA public key structure
 */
static void asu_rsa_free_publickey(struct rsa_public_key *s)
{
	if (s) {
		crypto_bignum_free(&s->n);
		crypto_bignum_free(&s->e);
	}
}

/**
 * asu_rsa_free_keypair() - Free RSA key-pair bignum fields
 * @s: RSA key-pair structure
 */
static void asu_rsa_free_keypair(struct rsa_keypair *s)
{
	if (!s)
		return;

	crypto_bignum_free(&s->e);
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->n);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->q);
	crypto_bignum_free(&s->qp);
	crypto_bignum_free(&s->dp);
	crypto_bignum_free(&s->dq);
}

/**
 * driver_rsa - ASU RSA driver structure
 */
static struct drvcrypt_rsa driver_rsa = {
	.alloc_publickey = asu_rsa_alloc_publickey,
	.free_publickey = asu_rsa_free_publickey,
	.alloc_keypair = asu_rsa_alloc_keypair,
	.free_keypair = asu_rsa_free_keypair,
	.gen_keypair = asu_rsa_gen_keypair,
	.encrypt = asu_rsa_encrypt,
	.decrypt = asu_rsa_decrypt,
	.optional.ssa_sign = asu_rsa_ssa_sign,
	.optional.ssa_verify = asu_rsa_ssa_verify,
};

static TEE_Result asu_rsa_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_rsa(&driver_rsa);
	if (ret) {
		EMSG("Failed to register ASU RSA ret=0x%x", ret);
		return ret;
	}

	IMSG("ASU RSA driver successfully initialized");

	return ret;
}

driver_init(asu_rsa_init);
