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
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <tee/cache.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

#define ASU_WORD_LEN_IN_BYTES				4U

/* ASU ECC/KeyManager Command IDs */
#define ASU_ECC_COMMAND_ID_SIGN				0x0U
#define ASU_ECC_COMMAND_ID_VERIFY			0x1U
#define ASU_ECC_COMMAND_ID_ECDH_SHARED_SECRET		0x3U
#define ASU_KM_COMMAND_ID_GEN_ECC_KEYPAIR		0x7U

/* ASU ECC status */
#define ASU_ECC_SIGNATURE_VERIFIED			0x3FCU
#define ASU_ECC_STATUS_CODE_MASK			0x3FFU
#define ASU_ECC_STATUS_CODE_SHIFT			10U
#define ASU_ECC_STATUS_RSA_ECC_BAD_SIGN			0x46U
#define ASU_ECC_STATUS_VERIFY_SIGN_OPERATION_FAIL	0x33U

/* ASU ECC private key sizes */
#define ASU_ECC_P192_PVT_KEY_SIZE_IN_BYTES		24U
#define ASU_ECC_P224_PVT_KEY_SIZE_IN_BYTES		28U
#define ASU_ECC_P256_PVT_KEY_SIZE_IN_BYTES		32U
#define ASU_ECC_P384_PVT_KEY_SIZE_IN_BYTES		48U
#define ASU_ECC_P521_PVT_KEY_SIZE_IN_BYTES		66U
#define ASU_ECC_MAX_HASH_SIZE_IN_BYTES			64U

/* Maximum private and public key buffer sizes across all supported curves */
#define ASU_ECC_MAX_PVT_KEY_SIZE_IN_BYTES \
		ASU_ECC_P521_PVT_KEY_SIZE_IN_BYTES
#define ASU_ECC_MAX_PUB_KEY_SIZE_IN_BYTES \
		(2U * ASU_ECC_MAX_PVT_KEY_SIZE_IN_BYTES)

#define ASU_KM_KEY_USAGE_COUNT_NON_DEPLETING_VALUE	0xFFFFFFFFU
#define ASU_KM_KEY_TYPE_ECC_PVT				4U
#define ASU_KM_KEY_USE_CASE_ALL				7U
#define ASU_KM_VAULT_ID					0U

/* ASU ECC curve IDs */
enum asu_ecc_curve_id {
	ASU_ECC_CURVE_NIST_P256 = 0U,
	ASU_ECC_CURVE_NIST_P384 = 1U,
	ASU_ECC_CURVE_NIST_P192 = 2U,
	ASU_ECC_CURVE_NIST_P224 = 3U,
	ASU_ECC_CURVE_NIST_P521 = 4U,
	ASU_ECC_CURVE_MAX       = 5U
};

/* Key object format used by ASU FW ECC/ECDH request payloads */
struct asu_ecc_key_object {
	uint64_t key_addr;
	uint32_t key_id;
	uint32_t key_len;
};

/* ECC sign/verify params passed to ASU firmware */
struct asu_ecc_params {
	struct asu_ecc_key_object key;
	uint64_t digest_addr;
	uint64_t sign_addr;
	uint32_t curve_type;
	uint32_t digest_len;
};

/* Key manager metadata for ECC key-pair generation */
struct asu_km_key_metadata {
	uint16_t key_id;
	uint8_t key_type;
	uint8_t vault_id;
	uint8_t key_use_case;
	uint8_t key_attributes;
	uint16_t length;
	uint32_t epoch_time;
	uint32_t usage_count;
	uint32_t reserved;
};

/* Key manager AES key object */
struct asu_aes_key_object {
	uint64_t key_address;
	uint32_t key_size;
	uint32_t key_src;
	uint32_t key_id;
};

/* Key manager params for ECC key-pair generation */
struct asu_km_params {
	struct asu_km_key_metadata key_metadata;
	struct asu_aes_key_object aes_key_obj;
	uint32_t wrapped_input_len;
	uint64_t key_object_addr;
	uint64_t key_id_addr;
};

/* Key object buffer layout expected by KeyManager ECC key-pair generation */
struct asu_ecc_keypair_object {
	uint8_t pub_key[ASU_ECC_MAX_PUB_KEY_SIZE_IN_BYTES];
	uint8_t priv_key[ASU_ECC_MAX_PVT_KEY_SIZE_IN_BYTES];
};

/* ECDH shared-secret params for ASU firmware */
struct asu_ecc_ecdh_params {
	struct asu_ecc_key_object pvt_key;
	struct asu_ecc_key_object pub_key;
	uint64_t shared_secret_addr;
	uint64_t shared_secret_obj_id_addr;
	uint32_t curve_type;
	uint8_t reserved[4];
};

/* Callback context for key pair generation */
struct asu_ecc_keypair_cbctx {
	struct ecc_keypair *key;	/* Destination ECC key pair */
	size_t key_len;			/* Key size in bytes */
	uint8_t *priv_key;		/* Private key buffer */
	uint8_t *pub_key;		/* Public key buffer (X||Y) */
};

/* Callback context for verify operation */
struct asu_ecc_verify_cbctx {
	uint32_t verify_status; /* Verify status returned by firmware */
};

/* ECC operation function pointers for SW fallback */
static const struct crypto_ecc_keypair_ops *sw_pair_ops;
static const struct crypto_ecc_public_ops *sw_pub_ops;

/* Bitmask of ECC curves enabled in OP-TEE build for ASU FW offload */
static uint32_t asu_ecc_hw_curves_mask;

/**
 * asu_ecc_set_hw_curves_mask() - Initialize HW curve bitmask from build config
 *
 * Sets a bit for each curve enabled for HW offload and logs the HW/SW
 * assignment for every supported curve. Call once during driver init.
 */
static void asu_ecc_set_hw_curves_mask(void)
{
#ifdef CFG_AMD_ASU_ECC_CURVE_NIST_P192
	asu_ecc_hw_curves_mask |= BIT(ASU_ECC_CURVE_NIST_P192);
#endif
#ifdef CFG_AMD_ASU_ECC_CURVE_NIST_P224
	asu_ecc_hw_curves_mask |= BIT(ASU_ECC_CURVE_NIST_P224);
#endif
#ifdef CFG_AMD_ASU_ECC_CURVE_NIST_P256
	asu_ecc_hw_curves_mask |= BIT(ASU_ECC_CURVE_NIST_P256);
#endif
#ifdef CFG_AMD_ASU_ECC_CURVE_NIST_P384
	asu_ecc_hw_curves_mask |= BIT(ASU_ECC_CURVE_NIST_P384);
#endif
#ifdef CFG_AMD_ASU_ECC_CURVE_NIST_P521
	asu_ecc_hw_curves_mask |= BIT(ASU_ECC_CURVE_NIST_P521);
#endif
#define CURVE_MODE(c) \
	((asu_ecc_hw_curves_mask & BIT(ASU_ECC_CURVE_##c)) ? "HW" : "SW")

	IMSG("ASU ECC: NIST_P192=%s NIST_P224=%s NIST_P256=%s",
	     CURVE_MODE(NIST_P192), CURVE_MODE(NIST_P224),
	     CURVE_MODE(NIST_P256));
	IMSG("ASU ECC: NIST_P384=%s NIST_P521=%s",
	     CURVE_MODE(NIST_P384), CURVE_MODE(NIST_P521));
#undef CURVE_MODE
}

/* Check if ECC curve is enabled for HW offload in build configuration */
static bool asu_ecc_curve_fw_enabled(enum asu_ecc_curve_id asu_curve_id)
{
	if (asu_curve_id >= ASU_ECC_CURVE_MAX)
		return false;
	return asu_ecc_hw_curves_mask & BIT(asu_curve_id);
}

/* ECC key-pair generation SW fallback for curves disabled in build config */
static TEE_Result asu_ecc_sw_gen_keypair(struct ecc_keypair *key,
					 size_t size_bits)
{
	if (!sw_pair_ops || !sw_pair_ops->generate)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return sw_pair_ops->generate(key, size_bits);
}

/* ECDSA sign SW fallback for curves disabled in build config */
static TEE_Result asu_ecc_sw_sign(struct drvcrypt_sign_data *sdata)
{
	if (!sw_pair_ops || !sw_pair_ops->sign || !sdata || !sdata->key)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return sw_pair_ops->sign(sdata->algo, sdata->key,
				 sdata->message.data, sdata->message.length,
				 sdata->signature.data,
				 &sdata->signature.length);
}

/* ECDSA verify SW fallback for curves disabled in build config */
static TEE_Result asu_ecc_sw_verify(struct drvcrypt_sign_data *sdata)
{
	if (!sw_pub_ops || !sw_pub_ops->verify || !sdata || !sdata->key)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return sw_pub_ops->verify(sdata->algo, sdata->key,
				  sdata->message.data, sdata->message.length,
				  sdata->signature.data,
				  sdata->signature.length);
}

/* ECDH shared-secret SW fallback for curves disabled in build config */
static TEE_Result asu_ecc_sw_shared_secret(struct drvcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_SUCCESS;
	unsigned long secret_len = 0;

	if (!sw_pair_ops || !sw_pair_ops->shared_secret || !sdata)
		return TEE_ERROR_NOT_IMPLEMENTED;

	secret_len = sdata->secret.length;
	ret = sw_pair_ops->shared_secret(sdata->key_priv, sdata->key_pub,
					 sdata->secret.data, &secret_len);
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER)
		sdata->secret.length = secret_len;

	return ret;
}

/**
 * asu_ecc_get_curve_info() - Map TEE curve ID and return ASU curve/key size
 * @tee_curve_id: TEE ECC curve ID
 * @asu_curve_id: Output ASU ECC curve ID
 * @key_len: Output curve component size in bytes
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_get_curve_info(uint32_t tee_curve_id,
					 enum asu_ecc_curve_id *asu_curve_id,
					 size_t *key_len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!asu_curve_id || !key_len)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (tee_curve_id) {
	case TEE_ECC_CURVE_NIST_P192:
		*asu_curve_id = ASU_ECC_CURVE_NIST_P192;
		*key_len = ASU_ECC_P192_PVT_KEY_SIZE_IN_BYTES;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*asu_curve_id = ASU_ECC_CURVE_NIST_P224;
		*key_len = ASU_ECC_P224_PVT_KEY_SIZE_IN_BYTES;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*asu_curve_id = ASU_ECC_CURVE_NIST_P256;
		*key_len = ASU_ECC_P256_PVT_KEY_SIZE_IN_BYTES;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*asu_curve_id = ASU_ECC_CURVE_NIST_P384;
		*key_len = ASU_ECC_P384_PVT_KEY_SIZE_IN_BYTES;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*asu_curve_id = ASU_ECC_CURVE_NIST_P521;
		*key_len = ASU_ECC_P521_PVT_KEY_SIZE_IN_BYTES;
		break;
	default:
		EMSG("curve %#" PRIx32 " not supported", tee_curve_id);
		ret = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	if (ret == TEE_SUCCESS && !asu_ecc_curve_fw_enabled(*asu_curve_id)) {
		DMSG("Curve %#" PRIx32 " disabled, using SW fallback",
		     tee_curve_id);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	return ret;
}

/**
 * asu_ecc_alloc_keypair() - Allocate ECC key-pair bignums
 * @key: ECC key-pair object
 * @type: Requested key type
 * @size_bits: Component size in bits
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_alloc_keypair(struct ecc_keypair *key,
					uint32_t type,
					size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!key || !size_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	/* This driver supports both ECDH and ECDSA key pairs */
	if (type != TEE_TYPE_ECDSA_KEYPAIR &&
	    type != TEE_TYPE_ECDH_KEYPAIR) {
		EMSG("Unsupported key pair type-%u", type);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	memset(key, 0, sizeof(*key));

	/* Key-pair bignums (d/x/y) are released by TEE core object cleanup. */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto ERR;
	}

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto ERR;
	}

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto ERR;
	}

	return ret;

ERR:
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);

	return ret;
}

/**
 * asu_ecc_alloc_publickey() - Allocate ECC public key bignums
 * @key: ECC public key object
 * @type: Requested key type (unused)
 * @size_bits: Component size in bits
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_alloc_publickey(struct ecc_public_key *key,
					  uint32_t type __unused,
					  size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!key || !size_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto ERR;
	}

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto ERR;
	}

	return ret;

ERR:
	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);

	return ret;
}

/**
 * asu_ecc_free_publickey() - Free ECC public key bignums
 * @key: ECC public key object
 */
static void asu_ecc_free_publickey(struct ecc_public_key *key)
{
	if (!key)
		return;

	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);
	memset(key, 0, sizeof(*key));
}

/**
 * asu_ecc_gen_keypair_cb() - Process ASU key pair generation callback
 * @cbptr: Callback context
 * @resp_buf: Response buffer (unused)
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_gen_keypair_cb(void *cbptr,
					 struct asu_resp_buf *resp_buf)
{
	TEE_Result ret = TEE_SUCCESS;
	struct asu_ecc_keypair_cbctx *cbctx = NULL;

	(void)resp_buf;

	cbctx = cbptr;

	if (!cbctx || !cbctx->key || !cbctx->key_len ||
	    !cbctx->priv_key || !cbctx->pub_key) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cache_operation(TEE_CACHEINVALIDATE, cbctx->priv_key, cbctx->key_len);
	cache_operation(TEE_CACHEINVALIDATE, cbctx->pub_key,
			cbctx->key_len * 2);

	ret = crypto_bignum_bin2bn(cbctx->priv_key, cbctx->key_len,
				   cbctx->key->d);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = crypto_bignum_bin2bn(cbctx->pub_key, cbctx->key_len,
				   cbctx->key->x);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = crypto_bignum_bin2bn(cbctx->pub_key + cbctx->key_len,
				   cbctx->key_len, cbctx->key->y);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

/**
 * asu_ecc_verify_cb() - Capture verify callback status from firmware
 * @cbptr: Callback context
 * @resp_buf: ASU response buffer
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_verify_cb(void *cbptr,
				    struct asu_resp_buf *resp_buf)
{
	struct asu_ecc_verify_cbctx *cbctx = NULL;

	cbctx = cbptr;

	if (!cbctx || !resp_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Capture verify status returned by ASU FW */
	cbctx->verify_status = resp_buf->additionalstatus;

	return TEE_SUCCESS;
}

/**
 * asu_ecc_bn2bin_pad() - Export bignum as fixed-length big-endian buffer
 * @bn: Source bignum
 * @out: Output buffer
 * @out_len: Output buffer size in bytes
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_bn2bin_pad(struct bignum *bn, uint8_t *out,
				     size_t out_len)
{
	size_t bn_len = 0;

	if (!bn || !out || !out_len)
		return TEE_ERROR_BAD_PARAMETERS;

	bn_len = crypto_bignum_num_bytes(bn);
	if (bn_len > out_len)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(out, 0, out_len);
	crypto_bignum_bn2bin(bn, out + (out_len - bn_len));

	return TEE_SUCCESS;
}

/**
 * asu_ecc_encode_pubkey() - Encode ECC public key as X || Y
 * @x: Public key X coordinate
 * @y: Public key Y coordinate
 * @out: Output buffer for encoded public key
 * @key_len: Fixed size in bytes for each coordinate
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_encode_pubkey(struct bignum *x, struct bignum *y,
					uint8_t *out, size_t key_len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!x || !y || !out || !key_len)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = asu_ecc_bn2bin_pad(x, out, key_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = asu_ecc_bn2bin_pad(y, out + key_len, key_len);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

/**
 * asu_ecc_gen_keypair() - Generate ECC key pair via ASU firmware
 * @key: ECC key pair to populate
 * @size_bits: Requested size in bits (unused, derived from curve)
 *
 * Return: TEE_SUCCESS on success, or an error code.
 *
 */
static TEE_Result asu_ecc_gen_keypair(struct ecc_keypair *key,
				      size_t size_bits __unused)
{
	uint32_t header = 0;
	uint8_t req_len_words = 0;
	TEE_Result ret = TEE_SUCCESS;
	struct asu_km_params km_params = { };
	uint32_t status = 0;
	size_t key_len = 0;
	enum asu_ecc_curve_id asu_curve_id = ASU_ECC_CURVE_MAX;
	uint8_t unique_id = ASU_UNIQUE_ID_MAX;
	struct asu_client_params cparams = { };
	struct asu_ecc_keypair_cbctx kp_cbctx = { };
	struct asu_ecc_keypair_object keypair_obj __aligned(64);
	uint8_t uid_allocated = 0U;

	if (!key) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	ret = asu_ecc_get_curve_info(key->curve, &asu_curve_id, &key_len);
	/* Use software fallback if curve is disabled in build config */
	if (ret == TEE_ERROR_NOT_IMPLEMENTED)
		return asu_ecc_sw_gen_keypair(key, size_bits);
	else if (ret != TEE_SUCCESS)
		goto OUT;

	unique_id = asu_alloc_unique_id();
	if (unique_id == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to allocate unique ID");
		ret = TEE_ERROR_BUSY;
		goto OUT;
	}
	uid_allocated = 1U;

	req_len_words =
		(uint8_t)(sizeof(km_params) / ASU_WORD_LEN_IN_BYTES);
	header = asu_create_header(ASU_KM_COMMAND_ID_GEN_ECC_KEYPAIR,
				   unique_id,
				   ASU_MODULE_KEYMANAGER_ID,
				   req_len_words);

	cparams.priority = ASU_PRIORITY_HIGH;
	cparams.cbhandler = asu_ecc_gen_keypair_cb;
	cparams.cbptr = &kp_cbctx;

	kp_cbctx.key = key;
	kp_cbctx.key_len = key_len;
	kp_cbctx.priv_key = keypair_obj.priv_key;
	kp_cbctx.pub_key = keypair_obj.pub_key;

	memset(&keypair_obj, 0, sizeof(keypair_obj));

	cache_operation(TEE_CACHEFLUSH, &keypair_obj, sizeof(keypair_obj));

	km_params.key_metadata.key_id = 0U;
	km_params.key_metadata.key_type = ASU_KM_KEY_TYPE_ECC_PVT;
	km_params.key_metadata.vault_id = ASU_KM_VAULT_ID;
	km_params.key_metadata.key_use_case = ASU_KM_KEY_USE_CASE_ALL;
	km_params.key_metadata.length = (uint16_t)key_len;
	km_params.key_metadata.key_attributes = (uint8_t)asu_curve_id;
	km_params.key_metadata.epoch_time = 0U;
	km_params.key_metadata.usage_count =
		ASU_KM_KEY_USAGE_COUNT_NON_DEPLETING_VALUE;
	km_params.key_metadata.reserved = 0U;
	km_params.wrapped_input_len = 0U;
	km_params.key_object_addr = virt_to_phys(&keypair_obj);
	km_params.key_id_addr = 0;

	ret = asu_update_queue_buffer_n_send_ipi(&cparams, &km_params,
						 sizeof(km_params),
						 header,
						 &status);

	if (ret != TEE_SUCCESS) {
		EMSG("ASU key pair generation request failed: %#" PRIx32, ret);
		goto OUT;
	}

	if (status) {
		EMSG("FW error 0x%x", status);
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}
	DMSG("ECC key pair generated successfully by ASU FW");
	ret = TEE_SUCCESS;

OUT:
	if (uid_allocated)
		asu_free_unique_id(unique_id);
	memzero_explicit(&keypair_obj, sizeof(keypair_obj));

	return ret;
}

/**
 * asu_ecc_sign() - Perform ECDSA signature generation via ASU firmware
 * @sdata: Signature operation context
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_sign(struct drvcrypt_sign_data *sdata)
{
	uint32_t header = 0;
	uint8_t req_len_words = 0;
	TEE_Result ret = TEE_SUCCESS;
	struct asu_ecc_params ecc_params = { };
	struct ecc_keypair *key = NULL;
	uint32_t status = 0;
	size_t key_len = 0;
	size_t required_sig_len = 0;
	size_t digest_len = 0;
	enum asu_ecc_curve_id asu_curve_id = ASU_ECC_CURVE_MAX;
	uint8_t unique_id = ASU_UNIQUE_ID_MAX;
	struct asu_client_params cparams = { };
	uint8_t priv_key[ASU_ECC_MAX_PVT_KEY_SIZE_IN_BYTES] __aligned(64);
	uint8_t uid_allocated = 0U;

	if (!sdata || !sdata->key || !sdata->signature.data ||
	    !sdata->message.data || !sdata->message.length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	key = sdata->key;

	/* Validate curve and derive key length before acquiring any resource */
	ret = asu_ecc_get_curve_info(key->curve, &asu_curve_id, &key_len);
	/* Use software fallback if curve is disabled in build config */
	if (ret == TEE_ERROR_NOT_IMPLEMENTED)
		return asu_ecc_sw_sign(sdata);
	else if (ret != TEE_SUCCESS)
		goto OUT;

	required_sig_len = 2U * key_len;
	if (sdata->signature.length < required_sig_len) {
		sdata->signature.length = required_sig_len;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto OUT;
	}

	digest_len = sdata->message.length;
	if (digest_len > ASU_ECC_MAX_HASH_SIZE_IN_BYTES) {
		EMSG("Digest length %zu exceeds maximum supported %u",
		     digest_len, ASU_ECC_MAX_HASH_SIZE_IN_BYTES);
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto OUT;
	}

	memset(priv_key, 0, sizeof(priv_key));
	ret = asu_ecc_bn2bin_pad(key->d, priv_key, key_len);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to convert private key to binary");
		goto OUT;
	}

	unique_id = asu_alloc_unique_id();
	if (unique_id == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to allocate unique ID");
		ret = TEE_ERROR_BUSY;
		goto OUT;
	}
	uid_allocated = 1U;

	req_len_words =
		(uint8_t)(sizeof(ecc_params) / ASU_WORD_LEN_IN_BYTES);
	header = asu_create_header(ASU_ECC_COMMAND_ID_SIGN,
				   unique_id,
				   ASU_MODULE_ECC_ID,
				   req_len_words);

	cparams.priority = ASU_PRIORITY_HIGH;

	cache_operation(TEE_CACHEFLUSH, priv_key, key_len);
	cache_operation(TEE_CACHEFLUSH, sdata->message.data, digest_len);
	cache_operation(TEE_CACHEFLUSH, sdata->signature.data,
			required_sig_len);

	ecc_params.key.key_addr = virt_to_phys(priv_key);
	ecc_params.key.key_id = 0U;
	ecc_params.key.key_len = (uint32_t)key_len;
	ecc_params.digest_addr = virt_to_phys(sdata->message.data);
	ecc_params.sign_addr = virt_to_phys(sdata->signature.data);
	ecc_params.curve_type = (uint32_t)asu_curve_id;
	ecc_params.digest_len = (uint32_t)digest_len;

	ret = asu_update_queue_buffer_n_send_ipi(&cparams, &ecc_params,
						 sizeof(ecc_params), header,
						 &status);

	if (ret != TEE_SUCCESS) {
		EMSG("ASU sign request failed: %#" PRIx32, ret);
		goto OUT;
	}

	if (status) {
		EMSG("FW error 0x%x", status);
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}

	cache_operation(TEE_CACHEINVALIDATE, sdata->signature.data,
			required_sig_len);
	sdata->signature.length = required_sig_len;
	DMSG("Signature generated (len=%zu)", sdata->signature.length);
	ret = TEE_SUCCESS;

OUT:
	if (uid_allocated)
		asu_free_unique_id(unique_id);
	memzero_explicit(priv_key, sizeof(priv_key));

	return ret;
}

/**
 * asu_ecc_verify() - Perform ECDSA signature verification via ASU firmware
 * @sdata: Signature operation context
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_verify(struct drvcrypt_sign_data *sdata)
{
	uint32_t header = 0;
	uint8_t req_len_words = 0;
	TEE_Result ret = TEE_SUCCESS;
	struct asu_ecc_params ecc_params = { };
	struct ecc_public_key *key = NULL;
	uint32_t status = 0;
	uint32_t fw_ecc_status = 0;
	size_t key_len = 0;
	size_t digest_len = 0;
	enum asu_ecc_curve_id asu_curve_id = ASU_ECC_CURVE_MAX;
	uint8_t unique_id = ASU_UNIQUE_ID_MAX;
	struct asu_client_params cparams = { };
	struct asu_ecc_verify_cbctx cbctx = { };
	uint8_t pub_key[ASU_ECC_MAX_PUB_KEY_SIZE_IN_BYTES] __aligned(64);
	uint8_t uid_allocated = 0U;

	if (!sdata || !sdata->key || !sdata->signature.data ||
	    !sdata->message.data || !sdata->message.length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	key = sdata->key;

	ret = asu_ecc_get_curve_info(key->curve, &asu_curve_id, &key_len);
	/* Use software fallback if curve is disabled in build config */
	if (ret == TEE_ERROR_NOT_IMPLEMENTED)
		return asu_ecc_sw_verify(sdata);
	else if (ret != TEE_SUCCESS)
		goto OUT;

	/* Signature must be exactly r || s, each component of key_len bytes */
	if (sdata->signature.length != 2 * key_len) {
		EMSG("Invalid signature length: got %zu, expected %zu",
		     sdata->signature.length, 2 * key_len);
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	digest_len = sdata->message.length;
	if (digest_len > ASU_ECC_MAX_HASH_SIZE_IN_BYTES) {
		EMSG("Digest length %zu exceeds maximum supported %u",
		     digest_len, ASU_ECC_MAX_HASH_SIZE_IN_BYTES);
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto OUT;
	}

	memset(pub_key, 0, sizeof(pub_key));
	ret = asu_ecc_encode_pubkey(key->x, key->y, pub_key, key_len);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to encode public key");
		goto OUT;
	}

	unique_id = asu_alloc_unique_id();
	if (unique_id == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to allocate unique ID");
		ret = TEE_ERROR_BUSY;
		goto OUT;
	}
	uid_allocated = 1U;

	req_len_words =
		(uint8_t)(sizeof(ecc_params) / ASU_WORD_LEN_IN_BYTES);
	header = asu_create_header(ASU_ECC_COMMAND_ID_VERIFY,
				   unique_id,
				   ASU_MODULE_ECC_ID,
				   req_len_words);

	cparams.priority = ASU_PRIORITY_HIGH;
	cparams.cbhandler = asu_ecc_verify_cb;
	cparams.cbptr = &cbctx;

	cache_operation(TEE_CACHEFLUSH, pub_key, key_len * 2);
	cache_operation(TEE_CACHEFLUSH, sdata->message.data, digest_len);
	cache_operation(TEE_CACHEFLUSH, sdata->signature.data,
			sdata->signature.length);

	ecc_params.key.key_addr = virt_to_phys(pub_key);
	ecc_params.key.key_id = 0U;
	ecc_params.key.key_len = (uint32_t)key_len;
	ecc_params.digest_addr = virt_to_phys(sdata->message.data);
	ecc_params.sign_addr = virt_to_phys(sdata->signature.data);
	ecc_params.curve_type = (uint32_t)asu_curve_id;
	ecc_params.digest_len = (uint32_t)digest_len;

	ret = asu_update_queue_buffer_n_send_ipi(&cparams, &ecc_params,
						 sizeof(ecc_params), header,
						 &status);

	if (ret != TEE_SUCCESS) {
		EMSG("ASU verify request failed: %#" PRIx32, ret);
		goto OUT;
	}

	if (status) {
		fw_ecc_status = ((uint32_t)status >> ASU_ECC_STATUS_CODE_SHIFT)
				& ASU_ECC_STATUS_CODE_MASK;

		EMSG("FW error 0x%x", status);

		if (fw_ecc_status ==
			ASU_ECC_STATUS_VERIFY_SIGN_OPERATION_FAIL ||
			(status & ASU_ECC_STATUS_CODE_MASK) ==
			ASU_ECC_STATUS_RSA_ECC_BAD_SIGN)
			ret = TEE_ERROR_SIGNATURE_INVALID;
		else
			ret = TEE_ERROR_GENERIC;

		goto OUT;
	}

	if (cbctx.verify_status != ASU_ECC_SIGNATURE_VERIFIED) {
		EMSG("ECC signature verification failed, status=%#" PRIx32,
		     cbctx.verify_status);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto OUT;
	}

	DMSG("ECC signature verified successfully by ASU FW");
	ret = TEE_SUCCESS;

OUT:
	if (uid_allocated)
		asu_free_unique_id(unique_id);
	memzero_explicit(pub_key, sizeof(pub_key));

	return ret;
}

/**
 * asu_ecc_shared_secret() - Compute ECDH shared secret via ASU firmware
 * @sdata: Shared-secret operation context
 *
 * Return: TEE_SUCCESS on success, or an error code.
 */
static TEE_Result asu_ecc_shared_secret(struct drvcrypt_secret_data *sdata)
{
	uint32_t header = 0;
	uint8_t req_len_words = 0;
	TEE_Result ret = TEE_SUCCESS;
	struct asu_ecc_ecdh_params ecdh_params = { };
	struct ecc_keypair *priv_key = NULL;
	struct ecc_public_key *pub_key = NULL;
	uint32_t status = 0;
	size_t key_len = 0;
	enum asu_ecc_curve_id asu_curve_id = ASU_ECC_CURVE_MAX;
	uint8_t unique_id = ASU_UNIQUE_ID_MAX;
	struct asu_client_params cparams = { };
	uint8_t priv_key_buf[ASU_ECC_MAX_PVT_KEY_SIZE_IN_BYTES] __aligned(64);
	uint8_t pub_key_buf[ASU_ECC_MAX_PUB_KEY_SIZE_IN_BYTES] __aligned(64);
	uint8_t shared_secret_buf[ASU_ECC_MAX_PVT_KEY_SIZE_IN_BYTES]
		__aligned(64);
	uint8_t uid_allocated = 0U;

	if (!sdata || !sdata->key_priv || !sdata->key_pub ||
	    !sdata->secret.data) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	priv_key = sdata->key_priv;
	pub_key  = sdata->key_pub;
	if (priv_key->curve != pub_key->curve) {
		EMSG("Curve mismatch: private %#" PRIx32 ", public %#" PRIx32,
		     priv_key->curve, pub_key->curve);
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto OUT;
	}

	ret = asu_ecc_get_curve_info(priv_key->curve, &asu_curve_id, &key_len);
	/* Use software fallback if curve is disabled in build config */
	if (ret == TEE_ERROR_NOT_IMPLEMENTED)
		return asu_ecc_sw_shared_secret(sdata);
	else if (ret != TEE_SUCCESS)
		goto OUT;

	if (sdata->secret.length < key_len) {
		EMSG("Secret buffer too small (need %zu, got %zu)",
		     key_len, sdata->secret.length);
		ret = TEE_ERROR_SHORT_BUFFER;
		goto OUT;
	}

	unique_id = asu_alloc_unique_id();
	if (unique_id == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to allocate unique ID");
		ret = TEE_ERROR_BUSY;
		goto OUT;
	}
	uid_allocated = 1U;

	req_len_words =
		(uint8_t)(sizeof(ecdh_params) / ASU_WORD_LEN_IN_BYTES);
	header = asu_create_header(ASU_ECC_COMMAND_ID_ECDH_SHARED_SECRET,
				   unique_id,
				   ASU_MODULE_ECC_ID,
				   req_len_words);

	cparams.priority = ASU_PRIORITY_HIGH;
	cparams.cbhandler = NULL;
	cparams.cbptr = NULL;

	/* Encode private key (big-endian, padded to key_len) */
	memset(priv_key_buf, 0, sizeof(priv_key_buf));
	ret = asu_ecc_bn2bin_pad(priv_key->d, priv_key_buf, key_len);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to encode private key");
		goto OUT;
	}

	/* Encode public key as X || Y, each component padded to key_len */
	memset(pub_key_buf, 0, sizeof(pub_key_buf));
	ret = asu_ecc_encode_pubkey(pub_key->x, pub_key->y,
				    pub_key_buf, key_len);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to encode public key");
		goto OUT;
	}

	memset(shared_secret_buf, 0, sizeof(shared_secret_buf));

	cache_operation(TEE_CACHEFLUSH, priv_key_buf, key_len);
	cache_operation(TEE_CACHEFLUSH, pub_key_buf, key_len * 2);
	cache_operation(TEE_CACHEFLUSH, shared_secret_buf, key_len);

	ecdh_params.pvt_key.key_addr = virt_to_phys(priv_key_buf);
	ecdh_params.pvt_key.key_id = 0U;
	ecdh_params.pvt_key.key_len = (uint32_t)key_len;
	ecdh_params.pub_key.key_addr = virt_to_phys(pub_key_buf);
	ecdh_params.pub_key.key_id = 0U;
	ecdh_params.pub_key.key_len = (uint32_t)key_len;
	ecdh_params.shared_secret_addr = virt_to_phys(shared_secret_buf);
	ecdh_params.shared_secret_obj_id_addr = 0;
	ecdh_params.curve_type = (uint32_t)asu_curve_id;

	ret = asu_update_queue_buffer_n_send_ipi(&cparams, &ecdh_params,
						 sizeof(ecdh_params), header,
						 &status);

	if (ret != TEE_SUCCESS) {
		EMSG("ASU shared secret request failed: %#" PRIx32, ret);
		goto OUT;
	}

	if (status) {
		EMSG("FW error 0x%x", status);
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}

	cache_operation(TEE_CACHEINVALIDATE, shared_secret_buf, key_len);

	memcpy(sdata->secret.data, shared_secret_buf, key_len);
	sdata->secret.length = key_len;
	DMSG("ECDH shared secret generated successfully by ASU FW");
	ret = TEE_SUCCESS;

OUT:
	if (uid_allocated)
		asu_free_unique_id(unique_id);
	memzero_explicit(priv_key_buf, sizeof(priv_key_buf));
	memzero_explicit(shared_secret_buf, sizeof(shared_secret_buf));

	return ret;
}

static struct drvcrypt_ecc asu_ecc_ops = {
	.alloc_keypair		= asu_ecc_alloc_keypair,
	.alloc_publickey	= asu_ecc_alloc_publickey,
	.free_publickey		= asu_ecc_free_publickey,
	.gen_keypair		= asu_ecc_gen_keypair,
	.sign			= asu_ecc_sign,
	.verify			= asu_ecc_verify,
	.shared_secret		= asu_ecc_shared_secret,
};

static TEE_Result asu_ecc_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	asu_ecc_set_hw_curves_mask();

	sw_pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!sw_pair_ops || !sw_pair_ops->generate || !sw_pair_ops->sign ||
	    !sw_pair_ops->shared_secret) {
		EMSG("ASU ECC software key-pair operations unavailable");
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}

	sw_pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!sw_pub_ops || !sw_pub_ops->verify) {
		EMSG("ASU ECC software public operations unavailable");
		ret = TEE_ERROR_GENERIC;
		goto OUT;
	}

	ret = drvcrypt_register_ecc(&asu_ecc_ops);
OUT:
	if (ret != TEE_SUCCESS)
		EMSG("ASU ECC register to crypto failed, ret=%#" PRIx32, ret);
	else
		DMSG("ASU ECC registered to crypto successfully");

	return ret;
}

driver_init(asu_ecc_init);
