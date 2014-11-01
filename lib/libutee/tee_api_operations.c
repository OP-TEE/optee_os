/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdlib.h>
#include <string.h>

#include <tee_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_syscalls.h>
#include <utee_defines.h>

struct __TEE_OperationHandle {
	TEE_OperationInfo info;
	TEE_ObjectHandle key1;
	TEE_ObjectHandle key2;
	uint8_t *buffer;	/* buffer to collect complete blocks */
	bool buffer_two_blocks;	/* True if two blocks need to be buffered */
	size_t block_size;	/* Block size of cipher */
	size_t buffer_offs;	/* Offset in buffer */
	uint32_t state;		/* Handle to state in TEE Core */
	uint32_t ae_tag_len;	/*
				 * tag_len in bytes for AE operation else unused
				 */
};

/* Cryptographic Operations API - Generic Operation Functions */

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
				 uint32_t algorithm, uint32_t mode,
				 uint32_t maxKeySize)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint32_t handle_state = 0;
	size_t block_size = 1;
	uint32_t req_key_usage;
	bool with_private_key = false;
	bool buffer_two_blocks = false;

	if (operation == NULL)
		TEE_Panic(0);

	if (algorithm == TEE_ALG_AES_XTS)
		handle_state = TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

	switch (algorithm) {
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
		buffer_two_blocks = true;
	 /*FALLTHROUGH*/ case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		if (TEE_ALG_GET_MAIN_ALG(algorithm) == TEE_MAIN_ALGO_AES)
			block_size = TEE_AES_BLOCK_SIZE;
		else
			block_size = TEE_DES_BLOCK_SIZE;

		if (mode == TEE_MODE_ENCRYPT)
			req_key_usage = TEE_USAGE_ENCRYPT;
		else if (mode == TEE_MODE_DECRYPT)
			req_key_usage = TEE_USAGE_DECRYPT;
		else
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_DSA_SHA1:
		if (mode == TEE_MODE_SIGN) {
			with_private_key = true;
			req_key_usage = TEE_USAGE_SIGN;
		} else if (mode == TEE_MODE_VERIFY) {
			req_key_usage = TEE_USAGE_VERIFY;
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
		break;

	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		if (mode == TEE_MODE_ENCRYPT) {
			req_key_usage = TEE_USAGE_ENCRYPT;
		} else if (mode == TEE_MODE_DECRYPT) {
			with_private_key = true;
			req_key_usage = TEE_USAGE_DECRYPT;
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
		break;

	case TEE_ALG_RSA_NOPAD:
		if (mode == TEE_MODE_ENCRYPT) {
			req_key_usage = TEE_USAGE_ENCRYPT | TEE_USAGE_VERIFY;
		} else if (mode == TEE_MODE_DECRYPT) {
			with_private_key = true;
			req_key_usage = TEE_USAGE_DECRYPT | TEE_USAGE_SIGN;
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		if (mode != TEE_MODE_DERIVE)
			return TEE_ERROR_NOT_SUPPORTED;
		with_private_key = true;
		req_key_usage = TEE_USAGE_DERIVE;
		break;

	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		if (mode != TEE_MODE_DIGEST)
			return TEE_ERROR_NOT_SUPPORTED;
		handle_state |= TEE_HANDLE_FLAG_KEY_SET;
		req_key_usage = 0;
		break;

	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (mode != TEE_MODE_MAC)
			return TEE_ERROR_NOT_SUPPORTED;
		req_key_usage = TEE_USAGE_MAC;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	op = TEE_Malloc(sizeof(*op), 0);
	if (op == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	op->info.algorithm = algorithm;
	op->info.operationClass = TEE_ALG_GET_CLASS(algorithm);
	op->info.mode = mode;
	op->info.maxKeySize = maxKeySize;
	op->info.requiredKeyUsage = req_key_usage;
	op->info.handleState = handle_state;

	if (block_size > 1) {
		size_t buffer_size = block_size;

		if (buffer_two_blocks)
			buffer_size *= 2;

		op->buffer =
		    TEE_Malloc(buffer_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (op->buffer == NULL) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}
	op->block_size = block_size;
	op->buffer_two_blocks = buffer_two_blocks;

	if (TEE_ALG_GET_CLASS(algorithm) != TEE_OPERATION_DIGEST) {
		uint32_t mks = maxKeySize;
		TEE_ObjectType key_type = TEE_ALG_GET_KEY_TYPE(algorithm,
						       with_private_key);

		/*
		 * If two keys are expected the max key size is the sum of
		 * the size of both keys.
		 */
		if (op->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS)
			mks /= 2;

		res = TEE_AllocateTransientObject(key_type, mks, &op->key1);
		if (res != TEE_SUCCESS)
			goto out;

		if ((op->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) !=
		    0) {
			res =
			    TEE_AllocateTransientObject(key_type, mks,
							&op->key2);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	res = utee_cryp_state_alloc(algorithm, mode, (uint32_t) op->key1,
				    (uint32_t) op->key2, &op->state);
	if (res != TEE_SUCCESS)
		goto out;

	/* For multi-stage operation do an "init". */
	TEE_ResetOperation(op);
	*operation = op;

out:
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(op->key1);
		TEE_FreeTransientObject(op->key2);
		TEE_FreeOperation(op);
	}

	return res;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	if (operation != TEE_HANDLE_NULL) {
		/*
		 * Note that keys should not be freed here, since they are
		 * claimed by the operation they will be freed by
		 * utee_cryp_state_free().
		 */
		utee_cryp_state_free(operation->state);
		TEE_Free(operation->buffer);
		TEE_Free(operation);
	}
}

void TEE_GetOperationInfo(TEE_OperationHandle operation,
			  TEE_OperationInfo *operationInfo)
{
	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	if (operationInfo == NULL)
		TEE_Panic(0);

	*operationInfo = operation->info;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);
	if (operation->info.operationClass == TEE_OPERATION_DIGEST) {
		res = utee_hash_init(operation->state, NULL, 0);
		if (res != TEE_SUCCESS)
			TEE_Panic(res);
	}
	operation->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
			       TEE_ObjectHandle key)
{
	uint32_t key_size = 0;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	/* No key for digests */
	if (operation->info.operationClass == TEE_OPERATION_DIGEST)
		TEE_Panic(0);

	/* Two keys expected */
	if ((operation->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) !=
	    0)
		TEE_Panic(0);

	if (key != TEE_HANDLE_NULL) {
		TEE_ObjectInfo key_info;

		TEE_GetObjectInfo(key, &key_info);
		/* Supplied key has to meet required usage */
		if ((key_info.objectUsage & operation->info.requiredKeyUsage) !=
		    operation->info.requiredKeyUsage) {
			TEE_Panic(0);
		}

		if (operation->info.maxKeySize < key_info.objectSize)
			TEE_Panic(0);

		key_size = key_info.objectSize;
	}

	TEE_ResetTransientObject(operation->key1);
	operation->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;

	if (key != TEE_HANDLE_NULL) {
		TEE_CopyObjectAttributes(operation->key1, key);
		operation->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	}

	operation->info.keySize = key_size;

	return TEE_SUCCESS;
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
				TEE_ObjectHandle key1, TEE_ObjectHandle key2)
{
	uint32_t key_size = 0;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	/* Two keys not expected */
	if ((operation->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) ==
	    0)
		TEE_Panic(0);

	/* Either both keys are NULL or both are not NULL */
	if ((key1 == TEE_HANDLE_NULL || key2 == TEE_HANDLE_NULL) &&
	    key1 != key2)
		TEE_Panic(0);

	if (key1 != TEE_HANDLE_NULL) {
		TEE_ObjectInfo key_info1;
		TEE_ObjectInfo key_info2;

		TEE_GetObjectInfo(key1, &key_info1);
		/* Supplied key has to meet required usage */
		if ((key_info1.objectUsage & operation->info.
		     requiredKeyUsage) != operation->info.requiredKeyUsage) {
			TEE_Panic(0);
		}

		TEE_GetObjectInfo(key2, &key_info2);
		/* Supplied key has to meet required usage */
		if ((key_info2.objectUsage & operation->info.
		     requiredKeyUsage) != operation->info.requiredKeyUsage) {
			TEE_Panic(0);
		}

		/*
		 * AES-XTS (the only multi key algorithm supported, requires the
		 * keys to be of equal size.
		 */
		if (operation->info.algorithm == TEE_ALG_AES_XTS &&
		    key_info1.objectSize != key_info2.objectSize)
			TEE_Panic(0);

		if (operation->info.maxKeySize < key_info1.objectSize)
			TEE_Panic(0);

		/*
		 * Odd that only the size of one key should be reported while
		 * size of two key are used when allocating the operation.
		 */
		key_size = key_info1.objectSize;
	}

	TEE_ResetTransientObject(operation->key1);
	TEE_ResetTransientObject(operation->key2);
	operation->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;

	if (key1 != TEE_HANDLE_NULL) {
		TEE_CopyObjectAttributes(operation->key1, key1);
		TEE_CopyObjectAttributes(operation->key2, key2);
		operation->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	}

	operation->info.keySize = key_size;

	return TEE_SUCCESS;
}

void TEE_CopyOperation(TEE_OperationHandle dst_op, TEE_OperationHandle src_op)
{
	TEE_Result res;

	if (dst_op == TEE_HANDLE_NULL || src_op == TEE_HANDLE_NULL)
		TEE_Panic(0);
	if (dst_op->info.algorithm != src_op->info.algorithm)
		TEE_Panic(0);
	if (src_op->info.operationClass != TEE_OPERATION_DIGEST) {
		TEE_ObjectHandle key1 = TEE_HANDLE_NULL;
		TEE_ObjectHandle key2 = TEE_HANDLE_NULL;

		if (src_op->info.handleState & TEE_HANDLE_FLAG_KEY_SET) {
			key1 = src_op->key1;
			key2 = src_op->key2;
		}

		if ((src_op->info.handleState &
		     TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) == 0) {
			TEE_SetOperationKey(dst_op, key1);
		} else {
			TEE_SetOperationKey2(dst_op, key1, key2);
		}
	}
	dst_op->info.handleState = src_op->info.handleState;
	dst_op->info.keySize = src_op->info.keySize;

	if (dst_op->buffer_two_blocks != src_op->buffer_two_blocks ||
	    dst_op->block_size != src_op->block_size)
		TEE_Panic(0);

	if (dst_op->buffer != NULL) {
		if (src_op->buffer == NULL)
			TEE_Panic(0);

		memcpy(dst_op->buffer, src_op->buffer, src_op->buffer_offs);
		dst_op->buffer_offs = src_op->buffer_offs;
	} else if (src_op->buffer != NULL) {
		TEE_Panic(0);
	}

	res = utee_cryp_state_copy(dst_op->state, src_op->state);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

/* Cryptographic Operations API - Message Digest Functions */

void TEE_DigestUpdate(TEE_OperationHandle operation,
		      void *chunk, size_t chunkSize)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (operation == TEE_HANDLE_NULL ||
	    operation->info.operationClass != TEE_OPERATION_DIGEST)
		TEE_Panic(0);

	res = utee_hash_update(operation->state, chunk, chunkSize);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, const void *chunk,
			     size_t chunkLen, void *hash, size_t *hashLen)
{
	if ((operation == TEE_HANDLE_NULL) || (!chunk && chunkLen) ||
	    !hash || !hashLen ||
	    (operation->info.operationClass != TEE_OPERATION_DIGEST))
		TEE_Panic(0);

	return utee_hash_final(operation->state, chunk, chunkLen, hash,
			       hashLen);
}

/* Cryptographic Operations API - Symmetric Cipher Functions */

void TEE_CipherInit(TEE_OperationHandle operation, const void *IV, size_t IVLen)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);
	if (operation->info.operationClass != TEE_OPERATION_CIPHER)
		TEE_Panic(0);
	res = utee_cipher_init(operation->state, IV, IVLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	operation->buffer_offs = 0;
	operation->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

static TEE_Result tee_buffer_update(
		TEE_OperationHandle op,
		TEE_Result(*update_func) (uint32_t state, const void *src,
					  size_t slen, void *dst, size_t *dlen),
		const void *src_data, size_t src_len,
		void *dest_data, size_t *dest_len)
{
	TEE_Result res;
	const uint8_t *src = src_data;
	size_t slen = src_len;
	uint8_t *dst = dest_data;
	size_t dlen = *dest_len;
	size_t acc_dlen = 0;
	size_t tmp_dlen;
	size_t l;
	size_t buffer_size;

	if (op->buffer_two_blocks)
		buffer_size = op->block_size * 2;
	else
		buffer_size = op->block_size;

	if (op->buffer_offs > 0) {
		/* Fill up complete block */
		if (op->buffer_offs < op->block_size)
			l = MIN(slen, op->block_size - op->buffer_offs);
		else
			l = MIN(slen, buffer_size - op->buffer_offs);
		memcpy(op->buffer + op->buffer_offs, src, l);
		op->buffer_offs += l;
		src += l;
		slen -= l;
		if ((op->buffer_offs % op->block_size) != 0)
			goto out;	/* Nothing left to do */
	}

	/* If we can feed from buffer */
	if (op->buffer_offs > 0 && (op->buffer_offs + slen) > buffer_size) {
		l = ROUNDUP(op->buffer_offs + slen - buffer_size,
				op->block_size);
		l = MIN(op->buffer_offs, l);
		tmp_dlen = dlen;
		res = update_func(op->state, op->buffer, l, dst, &tmp_dlen);
		if (res != TEE_SUCCESS)
			TEE_Panic(res);
		dst += tmp_dlen;
		dlen -= tmp_dlen;
		acc_dlen += tmp_dlen;
		op->buffer_offs -= l;
		if (op->buffer_offs > 0) {
			/*
			 * Slen is small enough to be contained in rest buffer.
			 */
			memcpy(op->buffer, op->buffer + l, buffer_size - l);
			memcpy(op->buffer + op->buffer_offs, src, slen);
			op->buffer_offs += slen;
			goto out;	/* Nothing left to do */
		}
	}

	if (slen > buffer_size) {
		/* Buffer is empty, feed as much as possible from src */
		if (TEE_ALIGNMENT_IS_OK(src, uint32_t)) {
			l = ROUNDUP(slen - buffer_size + 1, op->block_size);

			tmp_dlen = dlen;
			res = update_func(op->state, src, l, dst, &tmp_dlen);
			if (res != TEE_SUCCESS)
				TEE_Panic(res);
			src += l;
			slen -= l;
			dst += tmp_dlen;
			dlen -= tmp_dlen;
			acc_dlen += tmp_dlen;
		} else {
			/*
			 * Supplied data isn't well aligned, we're forced to
			 * feed through the buffer.
			 */
			while (slen >= op->block_size) {
				memcpy(op->buffer, src, op->block_size);

				tmp_dlen = dlen;
				res =
				    update_func(op->state, op->buffer,
						op->block_size, dst, &tmp_dlen);
				if (res != TEE_SUCCESS)
					TEE_Panic(res);
				src += op->block_size;
				slen -= op->block_size;
				dst += tmp_dlen;
				dlen -= tmp_dlen;
				acc_dlen += tmp_dlen;
			}
		}
	}

	/* Slen is small enough to be contained in buffer. */
	memcpy(op->buffer + op->buffer_offs, src, slen);
	op->buffer_offs += slen;

out:
	*dest_len = acc_dlen;
	return TEE_SUCCESS;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle op, const void *srcData,
			    size_t srcLen, void *destData, size_t *destLen)
{
	size_t req_dlen;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0))
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_CIPHER)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	/* Calculate required dlen */
	req_dlen = ((op->buffer_offs + srcLen) / op->block_size) *
	    op->block_size;
	if (op->buffer_two_blocks) {
		if (req_dlen > op->block_size * 2)
			req_dlen -= op->block_size * 2;
		else
			req_dlen = 0;
	}
	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_buffer_update(op, utee_cipher_update, srcData, srcLen, destData,
			  destLen);

	return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle op,
			     const void *srcData, size_t srcLen, void *destData,
			     size_t *destLen)
{
	TEE_Result res;
	uint8_t *dst = destData;
	size_t acc_dlen = 0;
	size_t tmp_dlen;
	size_t req_dlen;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0))
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_CIPHER)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	/*
	 * Check that the final block doesn't require padding for those
	 * algorithms that requires client to supply padding.
	 */
	if (op->info.algorithm == TEE_ALG_AES_ECB_NOPAD ||
	    op->info.algorithm == TEE_ALG_AES_CBC_NOPAD ||
	    op->info.algorithm == TEE_ALG_DES_ECB_NOPAD ||
	    op->info.algorithm == TEE_ALG_DES_CBC_NOPAD ||
	    op->info.algorithm == TEE_ALG_DES3_ECB_NOPAD ||
	    op->info.algorithm == TEE_ALG_DES3_CBC_NOPAD) {
		if (((op->buffer_offs + srcLen) % op->block_size) != 0)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	req_dlen = op->buffer_offs + srcLen;
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tmp_dlen = *destLen - acc_dlen;
	tee_buffer_update(op, utee_cipher_update, srcData, srcLen, dst,
			  &tmp_dlen);
	dst += tmp_dlen;
	acc_dlen += tmp_dlen;

	tmp_dlen = *destLen - acc_dlen;
	res = utee_cipher_final(op->state, op->buffer, op->buffer_offs,
				dst, &tmp_dlen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	acc_dlen += tmp_dlen;

	op->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	*destLen = acc_dlen;
	return TEE_SUCCESS;
}

/* Cryptographic Operations API - MAC Functions */

void TEE_MACInit(TEE_OperationHandle operation, const void *IV, size_t IVLen)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);
	if (IV == NULL && IVLen != 0)
		TEE_Panic(0);
	if (operation->info.operationClass != TEE_OPERATION_MAC)
		TEE_Panic(0);
	res = utee_hash_init(operation->state, IV, IVLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	operation->buffer_offs = 0;
	operation->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

void TEE_MACUpdate(TEE_OperationHandle op, const void *chunk, size_t chunkSize)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (chunk == NULL && chunkSize != 0))
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_MAC)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	res = utee_hash_update(op->state, chunk, chunkSize);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle op,
			       const void *message, size_t messageLen,
			       void *mac, size_t *macLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (message == NULL && messageLen != 0) ||
	    mac == NULL || macLen == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_MAC)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	res = utee_hash_final(op->state, message, messageLen, mac, macLen);
	op->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	return res;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
			       const void *message, size_t messageLen,
			       const void *mac, size_t macLen)
{
	TEE_Result res;
	uint8_t computed_mac[TEE_MAX_HASH_SIZE];
	size_t computed_mac_size = TEE_MAX_HASH_SIZE;

	res = TEE_MACComputeFinal(operation, message, messageLen, computed_mac,
				  &computed_mac_size);
	if (res != TEE_SUCCESS)
		return res;
	if (computed_mac_size != macLen)
		return TEE_ERROR_MAC_INVALID;
	if (memcmp(mac, computed_mac, computed_mac_size) != 0)
		return TEE_ERROR_MAC_INVALID;
	/* don't leave this on stack */
	memset(computed_mac, 0, computed_mac_size);
	return TEE_SUCCESS;
}

/* Cryptographic Operations API - Authenticated Encryption Functions */

TEE_Result TEE_AEInit(TEE_OperationHandle op, const void *nonce,
		      size_t nonceLen, uint32_t tagLen, uint32_t AADLen,
		      uint32_t payloadLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || nonce == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_AE)
		TEE_Panic(0);

	/*
	 * AES-CCM tag len is specified by AES-CCM spec and handled in TEE Core
	 * in the implementation. But AES-GCM spec doesn't specify the tag len
	 * according to the same principle so we have to check here instead to
	 * be GP compliant.
	 */
	if (op->info.algorithm == TEE_ALG_AES_GCM) {
		/*
		 * From GP spec: For AES-GCM, can be 128, 120, 112, 104, or 96
		 */
		if (tagLen < 96 || tagLen > 128 || (tagLen % 8 != 0))
			return TEE_ERROR_NOT_SUPPORTED;
	}

	res = utee_authenc_init(op->state, nonce, nonceLen, tagLen / 8, AADLen,
				payloadLen);
	if (res != TEE_SUCCESS) {
		if (res != TEE_ERROR_NOT_SUPPORTED)
			TEE_Panic(res);
		return res;
	}
	op->ae_tag_len = tagLen / 8;

	op->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	return TEE_SUCCESS;
}

void TEE_AEUpdateAAD(TEE_OperationHandle op, const void *AADdata,
		     size_t AADdataLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (AADdata == NULL && AADdataLen != 0))
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_AE)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	res = utee_authenc_update_aad(op->state, AADdata, AADdataLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle op, const void *srcData,
			size_t srcLen, void *destData, size_t *destLen)
{
	size_t req_dlen;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0))
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_AE)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	req_dlen = ROUNDDOWN(op->buffer_offs + srcLen, op->block_size);
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_buffer_update(op, utee_authenc_update_payload, srcData, srcLen,
			  destData, destLen);

	return TEE_SUCCESS;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle op,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t *tagLen)
{
	TEE_Result res;
	uint8_t *dst = destData;
	size_t acc_dlen = 0;
	size_t tmp_dlen;
	size_t req_dlen;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0) ||
	    tag == NULL || tagLen == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_AE)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	req_dlen = op->buffer_offs + srcLen;
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/*
	 * Need to check this before update_payload since sync would be lost if
	 * we return short buffer after that.
	 */
	if (*tagLen < op->ae_tag_len) {
		*tagLen = op->ae_tag_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tmp_dlen = *destLen - acc_dlen;
	tee_buffer_update(op, utee_authenc_update_payload, srcData, srcLen,
			  dst, &tmp_dlen);
	dst += tmp_dlen;
	acc_dlen += tmp_dlen;

	tmp_dlen = *destLen - acc_dlen;
	res =
	    utee_authenc_enc_final(op->state, op->buffer, op->buffer_offs, dst,
				   &tmp_dlen, tag, tagLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	acc_dlen += tmp_dlen;

	*destLen = acc_dlen;
	op->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

	return res;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle op,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, const void *tag,
			      size_t tagLen)
{
	TEE_Result res;
	uint8_t *dst = destData;
	size_t acc_dlen = 0;
	size_t tmp_dlen;
	size_t req_dlen;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0) ||
	    (tag == NULL && tagLen != 0))
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_AE)
		TEE_Panic(0);
	if ((op->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	req_dlen = op->buffer_offs + srcLen;
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tmp_dlen = *destLen - acc_dlen;
	tee_buffer_update(op, utee_authenc_update_payload, srcData, srcLen,
			  dst, &tmp_dlen);
	dst += tmp_dlen;
	acc_dlen += tmp_dlen;

	tmp_dlen = *destLen - acc_dlen;
	res =
	    utee_authenc_dec_final(op->state, op->buffer, op->buffer_offs, dst,
				   &tmp_dlen, tag, tagLen);
	if (res != TEE_SUCCESS && res != TEE_ERROR_MAC_INVALID)
		TEE_Panic(res);
	/* Supplied tagLen should match what we initiated with */
	if (tagLen != op->ae_tag_len)
		res = TEE_ERROR_MAC_INVALID;

	acc_dlen += tmp_dlen;

	*destLen = acc_dlen;
	op->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

	return res;
}

/* Cryptographic Operations API - Asymmetric Functions */

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle op,
				 const TEE_Attribute *params,
				 uint32_t paramCount, const void *srcData,
				 size_t srcLen, void *destData,
				 size_t *destLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0))
		TEE_Panic(0);
	if (paramCount != 0 && params == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER)
		TEE_Panic(0);
	if (op->info.mode != TEE_MODE_ENCRYPT)
		TEE_Panic(0);

	res = utee_asymm_operate(op->state, params, paramCount, srcData, srcLen,
				 destData, destLen);
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER &&
	    res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);
	return res;
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle op,
				 const TEE_Attribute *params,
				 uint32_t paramCount, const void *srcData,
				 size_t srcLen, void *destData,
				 size_t *destLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (srcData == NULL && srcLen != 0) ||
	    destLen == NULL || (destData == NULL && *destLen != 0))
		TEE_Panic(0);
	if (paramCount != 0 && params == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER)
		TEE_Panic(0);
	if (op->info.mode != TEE_MODE_DECRYPT)
		TEE_Panic(0);

	res = utee_asymm_operate(op->state, params, paramCount, srcData, srcLen,
				 destData, destLen);
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER &&
	    res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);
	return res;
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle op,
				    const TEE_Attribute *params,
				    uint32_t paramCount, const void *digest,
				    size_t digestLen, void *signature,
				    size_t *signatureLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (digest == NULL && digestLen != 0) ||
	    signature == NULL || signatureLen == NULL)
		TEE_Panic(0);
	if (paramCount != 0 && params == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE)
		TEE_Panic(0);
	if (op->info.mode != TEE_MODE_SIGN)
		TEE_Panic(0);

	res =
	    utee_asymm_operate(op->state, params, paramCount, digest, digestLen,
			       signature, signatureLen);
	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);
	return res;
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle op,
				      const TEE_Attribute *params,
				      uint32_t paramCount, const void *digest,
				      size_t digestLen, const void *signature,
				      size_t signatureLen)
{
	TEE_Result res;

	if (op == TEE_HANDLE_NULL || (digest == NULL && digestLen != 0) ||
	    (signature == NULL && signatureLen != 0))
		TEE_Panic(0);
	if (paramCount != 0 && params == NULL)
		TEE_Panic(0);
	if (op->info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE)
		TEE_Panic(0);
	if (op->info.mode != TEE_MODE_VERIFY)
		TEE_Panic(0);

	res =
	    utee_asymm_verify(op->state, params, paramCount, digest, digestLen,
			      signature, signatureLen);
	if (res != TEE_SUCCESS && res != TEE_ERROR_SIGNATURE_INVALID)
		TEE_Panic(res);
	return res;
}

/* Cryptographic Operations API - Key Derivation Functions */

void TEE_DeriveKey(TEE_OperationHandle operation,
		   const TEE_Attribute *params, uint32_t paramCount,
		   TEE_ObjectHandle derivedKey)
{
	TEE_Result res;
	TEE_ObjectInfo key_info;

	if (operation == TEE_HANDLE_NULL || derivedKey == 0)
		TEE_Panic(0);
	if (paramCount != 0 && params == NULL)
		TEE_Panic(0);

	if (operation->info.algorithm != TEE_ALG_DH_DERIVE_SHARED_SECRET)
		TEE_Panic(0);

	if (operation->info.operationClass != TEE_OPERATION_KEY_DERIVATION)
		TEE_Panic(0);
	if (operation->info.mode != TEE_MODE_DERIVE)
		TEE_Panic(0);
	if ((operation->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0)
		TEE_Panic(0);

	res = utee_cryp_obj_get_info((uint32_t) derivedKey, &key_info);
	if (res != TEE_SUCCESS)
		TEE_Panic(0);

	if (key_info.objectType != TEE_TYPE_GENERIC_SECRET)
		TEE_Panic(0);
	if ((key_info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		TEE_Panic(0);

	if ((operation->info.algorithm == TEE_ALG_DH_DERIVE_SHARED_SECRET) &&
	    (paramCount != 1 ||
	     params[0].attributeID != TEE_ATTR_DH_PUBLIC_VALUE))
		TEE_Panic(0);

	res = utee_cryp_derive_key(operation->state, params, paramCount,
				   (uint32_t) derivedKey);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

/* Cryptographic Operations API - Random Number Generation Functions */

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen)
{
	TEE_Result res;

	res = utee_cryp_random_number_generate(randomBuffer, randomBufferLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}
