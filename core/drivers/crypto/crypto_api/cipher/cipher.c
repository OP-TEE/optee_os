// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    cipher.c
 *
 * @brief   Crypto Cipher interface implementation to enable HW driver.
 */
/* Global includes */
#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <utee_defines.h>
#include <util.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>

const struct crypto_cipher_ops cipher_ops;

/**
 * @brief   Checks if input API context is correct. If not, system break.
 *          Returns the reference to the driver context
 *
 * @param[in] ctx  API Context
 *
 * @retval  Reference to the driver context
 */
static struct crypto_cipher *to_cipher_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &cipher_ops);

	return container_of(ctx, struct crypto_cipher, cipher_ctx);
}

/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo       Algorithm
 * @param[out] cipher_id  Cipher Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct drvcrypt_cipher *do_check_algo(uint32_t algo,
					enum drvcrypt_cipher_id *cipher_id)
{
	struct drvcrypt_cipher *cipher = NULL;
	uint8_t algo_op;
	uint8_t algo_id;
	uint8_t algo_md;
	uint8_t min_id;
	uint8_t max_id;
	enum drvcrypt_cipher_id cipher_algo = 0;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	algo_md = TEE_ALG_GET_CHAIN_MODE(algo);

	CRYPTO_TRACE("Algo op:%d id:%d md:%d", algo_op, algo_id, algo_md);

	if (algo_op == TEE_OPERATION_CIPHER) {
		switch (algo_id) {
		case TEE_MAIN_ALGO_AES:
			min_id = DRV_AES_ID;
			max_id = MAX_AES_ID;
			break;

		case TEE_MAIN_ALGO_DES:
			min_id = DRV_DES_ID;
			max_id = MAX_DES_ID;
			break;

		case TEE_MAIN_ALGO_DES3:
			min_id = DRV_DES3_ID;
			max_id = MAX_DES3_ID;
			break;

		default:
			return NULL;
		}

		cipher_algo = min_id + algo_md;

		if (cipher_algo < max_id) {
			cipher     = drvcrypt_getmod(CRYPTO_CIPHER);
			*cipher_id = cipher_algo;
		}
	}

	CRYPTO_TRACE("Check Cipher id: %d ret 0x%"PRIxPTR"",
				cipher_algo, (uintptr_t)cipher);

	return cipher;
}

/**
 * @brief   Free the Software Cipher Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 *
 */
static void cipher_free_ctx(struct crypto_cipher_ctx *ctx)
{
	struct crypto_cipher *cipher = to_cipher_ctx(ctx);

	/* Check the parameters */
	if (cipher) {
		if (cipher->op) {
			if (cipher->op->free_ctx)
				cipher->op->free_ctx(cipher->ctx);
		}

		free(cipher);
	}
}

/**
 * @brief   Copy Software Cipher Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void cipher_copy_state(struct crypto_cipher_ctx *dst_ctx,
		struct crypto_cipher_ctx *src_ctx)
{
	struct crypto_cipher *cipher_src = to_cipher_ctx(src_ctx);
	struct crypto_cipher *cipher_dst = to_cipher_ctx(dst_ctx);

	if ((!cipher_src) || (!cipher_dst))
		return;

	if (cipher_src->op) {
		if (cipher_src->op->cpy_state)
			cipher_src->op->cpy_state(cipher_dst->ctx,
				cipher_src->ctx);
	}
}

/**
 * @brief  Initialization of the Cipher operation
 *
 * @param[in] ctx      Reference the context pointer
 * @param[in] mode     Operation mode
 * @param[in] key1     First Key
 * @param[in] key1_len Length of the first key
 * @param[in] key2     Second Key
 * @param[in] key2_len Length of the second key
 * @param[in] iv       Initial Vector
 * @param[in] iv_len   Length of the IV
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result cipher_init(struct crypto_cipher_ctx *ctx,
					TEE_OperationMode mode,
					const uint8_t *key1, size_t key1_len,
					const uint8_t *key2, size_t key2_len,
					const uint8_t *iv, size_t iv_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_cipher     *cipher = to_cipher_ctx(ctx);
	struct drvcrypt_cipher_init dinit;

	/* Check the parameters */
	if (!cipher)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the mode */
	if ((mode != TEE_MODE_DECRYPT) && (mode != TEE_MODE_ENCRYPT)) {
		CRYPTO_TRACE("Bad Cipher mode request %d", mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the keys vs. length */
	if (((!key1) && (key1_len != 0)) ||
		((!key2) && (key2_len != 0)) ||
		((!iv) && (iv_len != 0))) {
		CRYPTO_TRACE("One of the key is bad");
		CRYPTO_TRACE("key1 @0x%08"PRIxPTR"-%d)",
			(uintptr_t)key1, key1_len);
		CRYPTO_TRACE("key2 @0x%08"PRIxPTR"-%d)",
			(uintptr_t)key1, key1_len);
		CRYPTO_TRACE("iv   @0x%08"PRIxPTR"-%d)",
			(uintptr_t)iv, iv_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cipher->op) {
		if (cipher->op->init) {
			/* Prepare the initialization data */
			dinit.ctx         = cipher->ctx;
			dinit.encrypt     = ((mode == TEE_MODE_ENCRYPT) ?
						true : false);
			dinit.key1.data   = (uint8_t *)key1;
			dinit.key1.length = key1_len;
			dinit.key2.data   = (uint8_t *)key2;
			dinit.key2.length = key2_len;
			dinit.iv.data     = (uint8_t *)iv;
			dinit.iv.length   = iv_len;
			ret = cipher->op->init(&dinit);
		}
	}

	CRYPTO_TRACE("cipher ret 0x%"PRIX32"", ret);
	return ret;
}

/**
 * @brief  Update of the Cipher operation
 *
 * @param[in]  ctx        Reference the context pointer
 * @param[in]  last_block True if last block to handle
 * @param[in]  data       Data to encrypt/decrypt
 * @param[in]  len        Length of the input data and output result
 * @param[out] dst        Result block of the operation
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_GENERIC           Other Error
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result cipher_update(struct crypto_cipher_ctx *ctx,
				bool last_block,
				const uint8_t *data, size_t len,
				uint8_t *dst)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_cipher       *cipher = to_cipher_ctx(ctx);
	struct drvcrypt_cipher_update dupdate;

	/* Check the parameters */
	if ((!ctx) || (!dst)) {
		CRYPTO_TRACE("Bad ctx @0x%08"PRIxPTR" or dst @0x%08"PRIxPTR"",
					(uintptr_t)ctx, (uintptr_t)dst);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the data vs. length */
	if ((!data) && (len != 0)) {
		CRYPTO_TRACE("Bad data data @0x%08"PRIxPTR"-%d)",
				(uintptr_t)data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the parameters */
	if (!cipher)
		return TEE_ERROR_BAD_PARAMETERS;

	if (cipher->op) {
		if (cipher->op->update) {
			/* Prepare the update data */
			dupdate.ctx         = cipher->ctx;
			dupdate.last        = last_block;
			dupdate.src.data    = (uint8_t *)data;
			dupdate.src.length  = len;
			dupdate.dst.data    = dst;
			dupdate.dst.length  = len;

			ret = cipher->op->update(&dupdate);
		}
	}

	CRYPTO_TRACE("cipher ret 0x%"PRIX32"", ret);
	return ret;
}

/**
 * @brief  Finalize the Cipher operation
 *
 * @param[in]  ctx        Reference the context pointer
 *
 */
static void cipher_final(struct crypto_cipher_ctx *ctx)
{
	struct crypto_cipher *cipher = to_cipher_ctx(ctx);

	/* Check the parameters */
	if (cipher) {
		if (cipher->op) {
			if (cipher->op->final)
				cipher->op->final(cipher->ctx);
		}
	}
}

const struct crypto_cipher_ops cipher_ops = {
	.init       = cipher_init,
	.update     = cipher_update,
	.final      = cipher_final,
	.free_ctx   = cipher_free_ctx,
	.copy_state = cipher_copy_state,
};

/**
 * @brief   Allocates the Software Cipher Context function of the algorithm
 *          and if the HW handles it. Else return on error and let the
 *          global cryptographic core module to call SW library enabled.
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result drvcrypt_cipher_alloc_ctx(struct crypto_cipher_ctx **ctx,
		uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_cipher *cipher   = NULL;
	enum drvcrypt_cipher_id cipher_id = 0;

	CRYPTO_TRACE("Cipher alloc_ctx algo 0x%"PRIX32"", algo);

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = calloc(1, sizeof(*cipher));
	if (!cipher)
		return TEE_ERROR_OUT_OF_MEMORY;

	cipher->op = do_check_algo(algo, &cipher_id);
	if (cipher->op) {
		if (cipher->op->alloc_ctx)
			ret = cipher->op->alloc_ctx(&cipher->ctx, cipher_id);
	}
	if (ret != TEE_SUCCESS) {
		free(cipher);
		*ctx = NULL;
	} else {
		cipher->cipher_ctx.ops = &cipher_ops;
		*ctx = &cipher->cipher_ctx;
	}

	CRYPTO_TRACE("Cipher alloc_ctx ret 0x%"PRIX32"", ret);

	return ret;
}


