// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2021, SumUp Services GmbH
 */
#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api.h>
#include <tee_api_defines_extensions.h>
#include <tee_internal_api_extensions.h>
#include <utee_syscalls.h>
#include <utee_defines.h>
#include <util.h>
#include "tee_api_private.h"

struct __TEE_OperationHandle {
	TEE_OperationInfo info;
	TEE_ObjectHandle key1;
	TEE_ObjectHandle key2;
	uint32_t operationState;/* Operation state : INITIAL or ACTIVE */
	uint8_t *buffer;	/* buffer to collect complete blocks */
	bool buffer_two_blocks;	/* True if two blocks need to be buffered */
	size_t block_size;	/* Block size of cipher */
	size_t buffer_offs;	/* Offset in buffer */
	uint32_t state;		/* Handle to state in TEE Core */
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

	if (!operation)
		TEE_Panic(0);

	if (algorithm == TEE_ALG_AES_XTS || algorithm == TEE_ALG_SM2_KEP)
		handle_state = TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

	/* Check algorithm max key size */
	switch (algorithm) {
	case TEE_ALG_DSA_SHA1:
		if (maxKeySize < 512)
			return TEE_ERROR_NOT_SUPPORTED;
		if (maxKeySize > 1024)
			return TEE_ERROR_NOT_SUPPORTED;
		if (maxKeySize % 64 != 0)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_DSA_SHA224:
		if (maxKeySize != 2048)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_DSA_SHA256:
		if (maxKeySize != 2048 && maxKeySize != 3072)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_ECDSA_P192:
	case TEE_ALG_ECDH_P192:
		if (maxKeySize != 192)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_ECDSA_P224:
	case TEE_ALG_ECDH_P224:
		if (maxKeySize != 224)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_ECDSA_P256:
	case TEE_ALG_ECDH_P256:
	case TEE_ALG_SM2_PKE:
	case TEE_ALG_SM2_DSA_SM3:
		if (maxKeySize != 256)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_SM2_KEP:
		/* Two 256-bit keys */
		if (maxKeySize != 512)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_ECDSA_P384:
	case TEE_ALG_ECDH_P384:
		if (maxKeySize != 384)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	case TEE_ALG_ECDSA_P521:
	case TEE_ALG_ECDH_P521:
		if (maxKeySize != 521)
			return TEE_ERROR_NOT_SUPPORTED;
		break;

	default:
		break;
	}

	/* Check algorithm mode (and maxKeySize for digests) */
	switch (algorithm) {
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
		buffer_two_blocks = true;
		fallthrough;
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_SM4_ECB_NOPAD:
	case TEE_ALG_SM4_CBC_NOPAD:
	case TEE_ALG_SM4_CTR:
		if (TEE_ALG_GET_MAIN_ALG(algorithm) == TEE_MAIN_ALGO_AES)
			block_size = TEE_AES_BLOCK_SIZE;
		else if (TEE_ALG_GET_MAIN_ALG(algorithm) == TEE_MAIN_ALGO_SM4)
			block_size = TEE_SM4_BLOCK_SIZE;
		else
			block_size = TEE_DES_BLOCK_SIZE;
		fallthrough;
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_GCM:
		if (mode == TEE_MODE_ENCRYPT)
			req_key_usage = TEE_USAGE_ENCRYPT;
		else if (mode == TEE_MODE_DECRYPT)
			req_key_usage = TEE_USAGE_DECRYPT;
		else
			return TEE_ERROR_NOT_SUPPORTED;
		break;

#if defined(CFG_CRYPTO_RSASSA_NA1)
	case TEE_ALG_RSASSA_PKCS1_V1_5:
#endif
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
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_DSA_SHA256:
	case TEE_ALG_ECDSA_P192:
	case TEE_ALG_ECDSA_P224:
	case TEE_ALG_ECDSA_P256:
	case TEE_ALG_ECDSA_P384:
	case TEE_ALG_ECDSA_P521:
	case TEE_ALG_SM2_DSA_SM3:
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
	case TEE_ALG_SM2_PKE:
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
	case TEE_ALG_ECDH_P192:
	case TEE_ALG_ECDH_P224:
	case TEE_ALG_ECDH_P256:
	case TEE_ALG_ECDH_P384:
	case TEE_ALG_ECDH_P521:
	case TEE_ALG_HKDF_MD5_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA1_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA224_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA256_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA384_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA512_DERIVE_KEY:
	case TEE_ALG_CONCAT_KDF_SHA1_DERIVE_KEY:
	case TEE_ALG_CONCAT_KDF_SHA224_DERIVE_KEY:
	case TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY:
	case TEE_ALG_CONCAT_KDF_SHA384_DERIVE_KEY:
	case TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY:
	case TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY:
	case TEE_ALG_SM2_KEP:
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
	case TEE_ALG_SM3:
		if (mode != TEE_MODE_DIGEST)
			return TEE_ERROR_NOT_SUPPORTED;
		if (maxKeySize)
			return TEE_ERROR_NOT_SUPPORTED;
		/* v1.1: flags always set for digest operations */
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
	case TEE_ALG_DES3_CMAC:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_HMAC_SM3:
		if (mode != TEE_MODE_MAC)
			return TEE_ERROR_NOT_SUPPORTED;
		req_key_usage = TEE_USAGE_MAC;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	op = TEE_Malloc(sizeof(*op), TEE_MALLOC_FILL_ZERO);
	if (!op)
		return TEE_ERROR_OUT_OF_MEMORY;

	op->info.algorithm = algorithm;
	op->info.operationClass = TEE_ALG_GET_CLASS(algorithm);
#ifdef CFG_CRYPTO_RSASSA_NA1
	if (algorithm == TEE_ALG_RSASSA_PKCS1_V1_5)
		op->info.operationClass = TEE_OPERATION_ASYMMETRIC_SIGNATURE;
#endif
	op->info.mode = mode;
	op->info.digestLength = TEE_ALG_GET_DIGEST_SIZE(algorithm);
	op->info.maxKeySize = maxKeySize;
	op->info.requiredKeyUsage = req_key_usage;
	op->info.handleState = handle_state;

	if (block_size > 1) {
		size_t buffer_size = block_size;

		if (buffer_two_blocks)
			buffer_size *= 2;

		op->buffer = TEE_Malloc(buffer_size,
					TEE_USER_MEM_HINT_NO_FILL_ZERO);
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

		if (op->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) {
			res = TEE_AllocateTransientObject(key_type, mks,
							  &op->key2);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	res = _utee_cryp_state_alloc(algorithm, mode, (unsigned long)op->key1,
				     (unsigned long)op->key2, &op->state);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * Initialize digest operations
	 * Other multi-stage operations initialized w/ TEE_xxxInit functions
	 * Non-applicable on asymmetric operations
	 */
	if (TEE_ALG_GET_CLASS(algorithm) == TEE_OPERATION_DIGEST) {
		res = _utee_hash_init(op->state, NULL, 0);
		if (res != TEE_SUCCESS)
			goto out;
		/* v1.1: flags always set for digest operations */
		op->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	}

	op->operationState = TEE_OPERATION_STATE_INITIAL;

	*operation = op;

out:
	if (res != TEE_SUCCESS) {
		if (res != TEE_ERROR_OUT_OF_MEMORY &&
		    res != TEE_ERROR_NOT_SUPPORTED)
			TEE_Panic(res);
		if (op) {
			if (op->state) {
				TEE_FreeOperation(op);
			} else {
				TEE_Free(op->buffer);
				TEE_FreeTransientObject(op->key1);
				TEE_FreeTransientObject(op->key2);
				TEE_Free(op);
			}
		}
	}

	return res;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	/*
	 * Note that keys should not be freed here, since they are
	 * claimed by the operation they will be freed by
	 * utee_cryp_state_free().
	 */
	res = _utee_cryp_state_free(operation->state);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	TEE_Free(operation->buffer);
	TEE_Free(operation);
}

void TEE_GetOperationInfo(TEE_OperationHandle operation,
			  TEE_OperationInfo *operationInfo)
{
	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	__utee_check_out_annotation(operationInfo, sizeof(*operationInfo));

	*operationInfo = operation->info;
	if (operationInfo->handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) {
		operationInfo->keySize = 0;
		operationInfo->requiredKeyUsage = 0;
	}
}

TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle op,
					TEE_OperationInfoMultiple *op_info,
					uint32_t *size)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectInfo kinfo = { };
	size_t max_key_count = 0;
	bool two_keys = false;

	if (op == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	__utee_check_outbuf_annotation(op_info, size);

	if (*size < sizeof(*op_info)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	max_key_count = (*size - sizeof(*op_info)) /
			sizeof(TEE_OperationInfoKey);

	TEE_MemFill(op_info, 0, *size);

	/* Two keys flag (TEE_ALG_AES_XTS only) */
	two_keys = op->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

	if (op->info.mode == TEE_MODE_DIGEST) {
		op_info->numberOfKeys = 0;
	} else if (!two_keys) {
		if (max_key_count < 1) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		res = TEE_GetObjectInfo1(op->key1, &kinfo);
		/* Key1 is not a valid handle, "can't happen". */
		if (res)
			goto out;

		op_info->keyInformation[0].keySize = kinfo.keySize;
		op_info->keyInformation[0].requiredKeyUsage =
			op->info.requiredKeyUsage;
		op_info->numberOfKeys = 1;
	} else {
		if (max_key_count < 2) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		res = TEE_GetObjectInfo1(op->key1, &kinfo);
		/* Key1 is not a valid handle, "can't happen". */
		if (res)
			goto out;

		op_info->keyInformation[0].keySize = kinfo.keySize;
		op_info->keyInformation[0].requiredKeyUsage =
			op->info.requiredKeyUsage;

		res = TEE_GetObjectInfo1(op->key2, &kinfo);
		/* Key2 is not a valid handle, "can't happen". */
		if (res)
			goto out;

		op_info->keyInformation[1].keySize = kinfo.keySize;
		op_info->keyInformation[1].requiredKeyUsage =
			op->info.requiredKeyUsage;

		op_info->numberOfKeys = 2;
	}

	op_info->algorithm = op->info.algorithm;
	op_info->operationClass = op->info.operationClass;
	op_info->mode = op->info.mode;
	op_info->digestLength = op->info.digestLength;
	op_info->maxKeySize = op->info.maxKeySize;
	op_info->handleState = op->info.handleState;
	op_info->operationState = op->operationState;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	if (!(operation->info.handleState & TEE_HANDLE_FLAG_KEY_SET))
			TEE_Panic(0);

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

	if (operation->info.operationClass == TEE_OPERATION_DIGEST) {
		res = _utee_hash_init(operation->state, NULL, 0);
		if (res != TEE_SUCCESS)
			TEE_Panic(res);
		operation->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	} else {
		operation->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	}
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
			       TEE_ObjectHandle key)
{
	TEE_Result res;
	uint32_t key_size = 0;
	TEE_ObjectInfo key_info;

	if (operation == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_INITIAL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (key == TEE_HANDLE_NULL) {
		/* Operation key cleared */
		TEE_ResetTransientObject(operation->key1);
		operation->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;
		return TEE_SUCCESS;
	}

	/* No key for digest operation */
	if (operation->info.operationClass == TEE_OPERATION_DIGEST) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Two keys flag not expected (TEE_ALG_AES_XTS excluded) */
	if ((operation->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) !=
	    0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = TEE_GetObjectInfo1(key, &key_info);
	/* Key is not a valid handle */
	if (res != TEE_SUCCESS)
		goto out;

	/* Supplied key has to meet required usage */
	if ((key_info.objectUsage & operation->info.requiredKeyUsage) !=
	    operation->info.requiredKeyUsage) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->info.maxKeySize < key_info.keySize) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	key_size = key_info.keySize;

	TEE_ResetTransientObject(operation->key1);
	operation->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;

	res = TEE_CopyObjectAttributes1(operation->key1, key);
	if (res != TEE_SUCCESS)
		goto out;

	operation->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

	operation->info.keySize = key_size;

out:
	if (res != TEE_SUCCESS  &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
				TEE_ObjectHandle key1, TEE_ObjectHandle key2)
{
	TEE_Result res;
	uint32_t key_size = 0;
	TEE_ObjectInfo key_info1;
	TEE_ObjectInfo key_info2;

	if (operation == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_INITIAL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Key1/Key2 and/or are not initialized and
	 * Either both keys are NULL or both are not NULL
	 */
	if (!key1 && !key2) {
		/* Clear the keys */
		TEE_ResetTransientObject(operation->key1);
		TEE_ResetTransientObject(operation->key2);
		operation->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;
		return TEE_SUCCESS;
	} else if (!key1 || !key2) {
		/* Both keys are obviously not valid. */
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* No key for digest operation */
	if (operation->info.operationClass == TEE_OPERATION_DIGEST) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Two keys flag expected (TEE_ALG_AES_XTS and TEE_ALG_SM2_KEP only) */
	if ((operation->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) ==
	    0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = TEE_GetObjectInfo1(key1, &key_info1);
	/* Key1 is not a valid handle */
	if (res != TEE_SUCCESS)
		goto out;

	/* Supplied key has to meet required usage */
	if ((key_info1.objectUsage & operation->info.
	     requiredKeyUsage) != operation->info.requiredKeyUsage) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = TEE_GetObjectInfo1(key2, &key_info2);
	/* Key2 is not a valid handle */
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_CORRUPT_OBJECT)
			res = TEE_ERROR_CORRUPT_OBJECT_2;
		goto out;
	}

	/* Supplied key has to meet required usage */
	if ((key_info2.objectUsage & operation->info.
	     requiredKeyUsage) != operation->info.requiredKeyUsage) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * All the multi key algorithm currently supported requires the keys to
	 * be of equal size.
	 */
	if (key_info1.keySize != key_info2.keySize) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;

	}

	if (operation->info.maxKeySize < key_info1.keySize) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Odd that only the size of one key should be reported while
	 * size of two key are used when allocating the operation.
	 */
	key_size = key_info1.keySize;

	TEE_ResetTransientObject(operation->key1);
	TEE_ResetTransientObject(operation->key2);
	operation->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;

	res = TEE_CopyObjectAttributes1(operation->key1, key1);
	if (res != TEE_SUCCESS)
		goto out;
	res = TEE_CopyObjectAttributes1(operation->key2, key2);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_CORRUPT_OBJECT)
			res = TEE_ERROR_CORRUPT_OBJECT_2;
		goto out;
	}

	operation->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

	operation->info.keySize = key_size;

out:
	if (res != TEE_SUCCESS  &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_CORRUPT_OBJECT_2 &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE_2)
		TEE_Panic(res);

	return res;
}

void TEE_CopyOperation(TEE_OperationHandle dst_op, TEE_OperationHandle src_op)
{
	TEE_Result res;

	if (dst_op == TEE_HANDLE_NULL || src_op == TEE_HANDLE_NULL)
		TEE_Panic(0);
	if (dst_op->info.algorithm != src_op->info.algorithm)
		TEE_Panic(0);
	if (dst_op->info.mode != src_op->info.mode)
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
	dst_op->info.digestLength = src_op->info.digestLength;
	dst_op->operationState = src_op->operationState;

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

	res = _utee_cryp_state_copy(dst_op->state, src_op->state);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

/* Cryptographic Operations API - Message Digest Functions */

static void init_hash_operation(TEE_OperationHandle operation, const void *IV,
				uint32_t IVLen)
{
	TEE_Result res;

	/*
	 * Note : IV and IVLen are never used in current implementation
	 * This is why coherent values of IV and IVLen are not checked
	 */
	res = _utee_hash_init(operation->state, IV, IVLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
	operation->buffer_offs = 0;
	operation->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

void TEE_DigestUpdate(TEE_OperationHandle operation,
		      const void *chunk, uint32_t chunkSize)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (operation == TEE_HANDLE_NULL ||
	    operation->info.operationClass != TEE_OPERATION_DIGEST)
		TEE_Panic(0);

	operation->operationState = TEE_OPERATION_STATE_ACTIVE;

	res = _utee_hash_update(operation->state, chunk, chunkSize);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, const void *chunk,
			     uint32_t chunkLen, void *hash, uint32_t *hashLen)
{
	TEE_Result res;
	uint64_t hl;

	if ((operation == TEE_HANDLE_NULL) ||
	    (!chunk && chunkLen) ||
	    (operation->info.operationClass != TEE_OPERATION_DIGEST)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_inout_annotation(hashLen, sizeof(*hashLen));

	hl = *hashLen;
	res = _utee_hash_final(operation->state, chunk, chunkLen, hash, &hl);
	*hashLen = hl;
	if (res != TEE_SUCCESS)
		goto out;

	/* Reset operation state */
	init_hash_operation(operation, NULL, 0);

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

/* Cryptographic Operations API - Symmetric Cipher Functions */

void TEE_CipherInit(TEE_OperationHandle operation, const void *IV,
		    uint32_t IVLen)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	if (operation->info.operationClass != TEE_OPERATION_CIPHER)
		TEE_Panic(0);

	if (!(operation->info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    !(operation->key1))
		TEE_Panic(0);

	if (operation->operationState != TEE_OPERATION_STATE_INITIAL)
		TEE_ResetOperation(operation);

	operation->operationState = TEE_OPERATION_STATE_ACTIVE;

	res = _utee_cipher_init(operation->state, IV, IVLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	operation->buffer_offs = 0;
	operation->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

static TEE_Result tee_buffer_update(
		TEE_OperationHandle op,
		TEE_Result(*update_func)(unsigned long state, const void *src,
				size_t slen, void *dst, uint64_t *dlen),
		const void *src_data, size_t src_len,
		void *dest_data, uint64_t *dest_len)
{
	TEE_Result res;
	const uint8_t *src = src_data;
	size_t slen = src_len;
	uint8_t *dst = dest_data;
	size_t dlen = *dest_len;
	size_t acc_dlen = 0;
	uint64_t tmp_dlen;
	size_t l;
	size_t buffer_size;
	size_t buffer_left;

	if (!src) {
		if (slen)
			TEE_Panic(0);
		goto out;
	}

	if (op->buffer_two_blocks) {
		buffer_size = op->block_size * 2;
		buffer_left = 1;
	} else {
		buffer_size = op->block_size;
		buffer_left = 0;
	}

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
	if ((op->buffer_offs > 0) &&
	    ((op->buffer_offs + slen) >= (buffer_size + buffer_left))) {
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

	if (slen >= (buffer_size + buffer_left)) {
		/* Buffer is empty, feed as much as possible from src */
		if (op->info.algorithm == TEE_ALG_AES_CTS)
			l = ROUNDUP(slen - buffer_size, op->block_size);
		else
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
	}

	/* Slen is small enough to be contained in buffer. */
	memcpy(op->buffer + op->buffer_offs, src, slen);
	op->buffer_offs += slen;

out:
	*dest_len = acc_dlen;
	return TEE_SUCCESS;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, const void *srcData,
			    uint32_t srcLen, void *destData, uint32_t *destLen)
{
	TEE_Result res;
	size_t req_dlen;
	uint64_t dl;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_inout_annotation(destLen, sizeof(*destLen));

	if (operation->info.operationClass != TEE_OPERATION_CIPHER) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_ACTIVE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (!srcData && !srcLen) {
		*destLen = 0;
		res = TEE_SUCCESS;
		goto out;
	}

	/* Calculate required dlen */
	if (operation->block_size > 1) {
		req_dlen = ((operation->buffer_offs + srcLen) /
			    operation->block_size) * operation->block_size;
	} else {
		req_dlen = srcLen;
	}
	if (operation->buffer_two_blocks) {
		if (req_dlen > operation->block_size * 2)
			req_dlen -= operation->block_size * 2;
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
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	dl = *destLen;
	if (operation->block_size > 1) {
		res = tee_buffer_update(operation, _utee_cipher_update, srcData,
					srcLen, destData, &dl);
	} else {
		if (srcLen > 0) {
			res = _utee_cipher_update(operation->state, srcData,
						  srcLen, destData, &dl);
		} else {
			res = TEE_SUCCESS;
			dl = 0;
		}
	}
	*destLen = dl;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
			     const void *srcData, uint32_t srcLen,
			     void *destData, uint32_t *destLen)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *dst = destData;
	size_t acc_dlen = 0;
	uint64_t tmp_dlen = 0;
	size_t req_dlen = 0;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (destLen)
		__utee_check_inout_annotation(destLen, sizeof(*destLen));

	if (operation->info.operationClass != TEE_OPERATION_CIPHER) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_ACTIVE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Check that the final block doesn't require padding for those
	 * algorithms that requires client to supply padding.
	 */
	if (operation->info.algorithm == TEE_ALG_AES_ECB_NOPAD ||
	    operation->info.algorithm == TEE_ALG_AES_CBC_NOPAD ||
	    operation->info.algorithm == TEE_ALG_DES_ECB_NOPAD ||
	    operation->info.algorithm == TEE_ALG_DES_CBC_NOPAD ||
	    operation->info.algorithm == TEE_ALG_DES3_ECB_NOPAD ||
	    operation->info.algorithm == TEE_ALG_DES3_CBC_NOPAD ||
	    operation->info.algorithm == TEE_ALG_SM4_ECB_NOPAD ||
	    operation->info.algorithm == TEE_ALG_SM4_CBC_NOPAD) {
		if (((operation->buffer_offs + srcLen) % operation->block_size)
		    != 0) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
	}

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	if (operation->block_size > 1) {
		req_dlen = operation->buffer_offs + srcLen;
	} else {
		req_dlen = srcLen;
	}
	if (destLen)
		tmp_dlen = *destLen;
	if (tmp_dlen < req_dlen) {
		if (destLen)
			*destLen = req_dlen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (operation->block_size > 1) {
		if (srcLen) {
			res = tee_buffer_update(operation, _utee_cipher_update,
						srcData, srcLen, dst,
						&tmp_dlen);
			if (res != TEE_SUCCESS)
				goto out;

			dst += tmp_dlen;
			acc_dlen += tmp_dlen;

			tmp_dlen = *destLen - acc_dlen;
		}
		res = _utee_cipher_final(operation->state, operation->buffer,
					 operation->buffer_offs, dst,
					 &tmp_dlen);
	} else {
		res = _utee_cipher_final(operation->state, srcData, srcLen, dst,
					 &tmp_dlen);
	}
	if (res != TEE_SUCCESS)
		goto out;

	acc_dlen += tmp_dlen;
	if (destLen)
		*destLen = acc_dlen;

	operation->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

/* Cryptographic Operations API - MAC Functions */

void TEE_MACInit(TEE_OperationHandle operation, const void *IV, uint32_t IVLen)
{
	if (operation == TEE_HANDLE_NULL)
		TEE_Panic(0);

	if (operation->info.operationClass != TEE_OPERATION_MAC)
		TEE_Panic(0);

	if (!(operation->info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    !(operation->key1))
		TEE_Panic(0);

	if (operation->operationState != TEE_OPERATION_STATE_INITIAL)
		TEE_ResetOperation(operation);

	operation->operationState = TEE_OPERATION_STATE_ACTIVE;

	init_hash_operation(operation, IV, IVLen);
}

void TEE_MACUpdate(TEE_OperationHandle operation, const void *chunk,
		   uint32_t chunkSize)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL || (chunk == NULL && chunkSize != 0))
		TEE_Panic(0);

	if (operation->info.operationClass != TEE_OPERATION_MAC)
		TEE_Panic(0);

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	if (operation->operationState != TEE_OPERATION_STATE_ACTIVE)
		TEE_Panic(0);

	res = _utee_hash_update(operation->state, chunk, chunkSize);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
			       const void *message, uint32_t messageLen,
			       void *mac, uint32_t *macLen)
{
	TEE_Result res;
	uint64_t ml;

	if (operation == TEE_HANDLE_NULL || (!message && messageLen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_inout_annotation(macLen, sizeof(*macLen));

	if (operation->info.operationClass != TEE_OPERATION_MAC) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_ACTIVE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ml = *macLen;
	res = _utee_hash_final(operation->state, message, messageLen, mac, &ml);
	*macLen = ml;
	if (res != TEE_SUCCESS)
		goto out;

	operation->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
			       const void *message, uint32_t messageLen,
			       const void *mac, uint32_t macLen)
{
	TEE_Result res;
	uint8_t computed_mac[TEE_MAX_HASH_SIZE] = { 0 };
	uint32_t computed_mac_size = TEE_MAX_HASH_SIZE;

	if (operation->info.operationClass != TEE_OPERATION_MAC) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_ACTIVE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = TEE_MACComputeFinal(operation, message, messageLen, computed_mac,
				  &computed_mac_size);
	if (res != TEE_SUCCESS)
		goto out;

	if (computed_mac_size != macLen) {
		res = TEE_ERROR_MAC_INVALID;
		goto out;
	}

	if (consttime_memcmp(mac, computed_mac, computed_mac_size) != 0) {
		res = TEE_ERROR_MAC_INVALID;
		goto out;
	}

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_MAC_INVALID)
		TEE_Panic(res);

	return res;
}

/* Cryptographic Operations API - Authenticated Encryption Functions */

TEE_Result TEE_AEInit(TEE_OperationHandle operation, const void *nonce,
		      uint32_t nonceLen, uint32_t tagLen, uint32_t AADLen,
		      uint32_t payloadLen)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL || nonce == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->info.operationClass != TEE_OPERATION_AE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (operation->operationState != TEE_OPERATION_STATE_INITIAL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * AES-CCM tag len is specified by AES-CCM spec and handled in TEE Core
	 * in the implementation. But AES-GCM spec doesn't specify the tag len
	 * according to the same principle so we have to check here instead to
	 * be GP compliant.
	 */
	if (operation->info.algorithm == TEE_ALG_AES_GCM) {
		/*
		 * From GP spec: For AES-GCM, can be 128, 120, 112, 104, or 96
		 */
		if (tagLen < 96 || tagLen > 128 || (tagLen % 8 != 0)) {
			res = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
	}

	res = _utee_authenc_init(operation->state, nonce, nonceLen, tagLen / 8,
				 AADLen, payloadLen);
	if (res != TEE_SUCCESS)
		goto out;

	operation->info.digestLength = tagLen / 8;
	operation->buffer_offs = 0;
	operation->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_NOT_SUPPORTED)
			TEE_Panic(res);

	return res;
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation, const void *AADdata,
		     uint32_t AADdataLen)
{
	TEE_Result res;

	if (operation == TEE_HANDLE_NULL ||
	    (AADdata == NULL && AADdataLen != 0))
		TEE_Panic(0);

	if (operation->info.operationClass != TEE_OPERATION_AE)
		TEE_Panic(0);

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		TEE_Panic(0);

	res = _utee_authenc_update_aad(operation->state, AADdata, AADdataLen);

	operation->operationState = TEE_OPERATION_STATE_ACTIVE;

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, const void *srcData,
			uint32_t srcLen, void *destData, uint32_t *destLen)
{
	TEE_Result res = TEE_SUCCESS;
	size_t req_dlen = 0;
	uint64_t dl = 0;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_inout_annotation(destLen, sizeof(*destLen));

	if (operation->info.operationClass != TEE_OPERATION_AE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (!srcData && !srcLen) {
		*destLen = 0;
		res = TEE_SUCCESS;
		goto out;
	}

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	if (operation->block_size > 1) {
		req_dlen = ROUNDDOWN(operation->buffer_offs + srcLen,
				     operation->block_size);
	} else {
		req_dlen = srcLen;
	}

	dl = *destLen;
	if (dl < req_dlen) {
		*destLen = req_dlen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (operation->block_size > 1) {
		res = tee_buffer_update(operation, _utee_authenc_update_payload,
					srcData, srcLen, destData, &dl);
	} else {
		if (srcLen > 0) {
			res = _utee_authenc_update_payload(operation->state,
							   srcData, srcLen,
							   destData, &dl);
		} else {
			dl = 0;
			res = TEE_SUCCESS;
		}
	}
	if (res != TEE_SUCCESS)
		goto out;

	*destLen = dl;

	operation->operationState = TEE_OPERATION_STATE_ACTIVE;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
			TEE_Panic(res);

	return res;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
			      const void *srcData, uint32_t srcLen,
			      void *destData, uint32_t *destLen, void *tag,
			      uint32_t *tagLen)
{
	TEE_Result res;
	uint8_t *dst = destData;
	size_t acc_dlen = 0;
	uint64_t tmp_dlen;
	size_t req_dlen;
	uint64_t tl;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_inout_annotation(destLen, sizeof(*destLen));
	__utee_check_inout_annotation(tagLen, sizeof(*tagLen));

	if (operation->info.operationClass != TEE_OPERATION_AE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 *
	 * Need to check this before update_payload since sync would be lost if
	 * we return short buffer after that.
	 */
	res = TEE_ERROR_GENERIC;

	req_dlen = operation->buffer_offs + srcLen;
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		res = TEE_ERROR_SHORT_BUFFER;
	}

	if (*tagLen < operation->info.digestLength) {
		*tagLen = operation->info.digestLength;
		res = TEE_ERROR_SHORT_BUFFER;
	}

	if (res == TEE_ERROR_SHORT_BUFFER)
		goto out;

	tl = *tagLen;
	tmp_dlen = *destLen - acc_dlen;
	if (operation->block_size > 1) {
		res = tee_buffer_update(operation, _utee_authenc_update_payload,
					srcData, srcLen, dst, &tmp_dlen);
		if (res != TEE_SUCCESS)
			goto out;

		dst += tmp_dlen;
		acc_dlen += tmp_dlen;

		tmp_dlen = *destLen - acc_dlen;
		res = _utee_authenc_enc_final(operation->state,
					      operation->buffer,
					      operation->buffer_offs, dst,
					      &tmp_dlen, tag, &tl);
	} else {
		res = _utee_authenc_enc_final(operation->state, srcData,
					      srcLen, dst, &tmp_dlen,
					      tag, &tl);
	}
	*tagLen = tl;
	if (res != TEE_SUCCESS)
		goto out;

	acc_dlen += tmp_dlen;
	*destLen = acc_dlen;

	operation->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER)
			TEE_Panic(res);

	return res;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
			      const void *srcData, uint32_t srcLen,
			      void *destData, uint32_t *destLen, void *tag,
			      uint32_t tagLen)
{
	TEE_Result res;
	uint8_t *dst = destData;
	size_t acc_dlen = 0;
	uint64_t tmp_dlen;
	size_t req_dlen;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_inout_annotation(destLen, sizeof(*destLen));

	if (operation->info.operationClass != TEE_OPERATION_AE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((operation->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Check that required destLen is big enough before starting to feed
	 * data to the algorithm. Errors during feeding of data are fatal as we
	 * can't restore sync with this API.
	 */
	req_dlen = operation->buffer_offs + srcLen;
	if (*destLen < req_dlen) {
		*destLen = req_dlen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	tmp_dlen = *destLen - acc_dlen;
	if (operation->block_size > 1) {
		res = tee_buffer_update(operation, _utee_authenc_update_payload,
					srcData, srcLen, dst, &tmp_dlen);
		if (res != TEE_SUCCESS)
			goto out;

		dst += tmp_dlen;
		acc_dlen += tmp_dlen;

		tmp_dlen = *destLen - acc_dlen;
		res = _utee_authenc_dec_final(operation->state,
					      operation->buffer,
					      operation->buffer_offs, dst,
					      &tmp_dlen, tag, tagLen);
	} else {
		res = _utee_authenc_dec_final(operation->state, srcData,
					      srcLen, dst, &tmp_dlen,
					      tag, tagLen);
	}
	if (res != TEE_SUCCESS)
		goto out;

	/* Supplied tagLen should match what we initiated with */
	if (tagLen != operation->info.digestLength)
		res = TEE_ERROR_MAC_INVALID;

	acc_dlen += tmp_dlen;
	*destLen = acc_dlen;

	operation->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

	operation->operationState = TEE_OPERATION_STATE_INITIAL;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER &&
	    res != TEE_ERROR_MAC_INVALID)
			TEE_Panic(res);

	return res;
}

/* Cryptographic Operations API - Asymmetric Functions */

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
				 const TEE_Attribute *params,
				 uint32_t paramCount, const void *srcData,
				 uint32_t srcLen, void *destData,
				 uint32_t *destLen)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_attribute ua[paramCount];
	uint64_t dl = 0;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen))
		TEE_Panic(0);

	__utee_check_attr_in_annotation(params, paramCount);
	__utee_check_inout_annotation(destLen, sizeof(*destLen));

	if (!operation->key1)
		TEE_Panic(0);
	if (operation->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER)
		TEE_Panic(0);
	if (operation->info.mode != TEE_MODE_ENCRYPT)
		TEE_Panic(0);

	__utee_from_attr(ua, params, paramCount);
	dl = *destLen;
	res = _utee_asymm_operate(operation->state, ua, paramCount, srcData,
				  srcLen, destData, &dl);
	*destLen = dl;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER &&
	    res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
				 const TEE_Attribute *params,
				 uint32_t paramCount, const void *srcData,
				 uint32_t srcLen, void *destData,
				 uint32_t *destLen)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_attribute ua[paramCount];
	uint64_t dl = 0;

	if (operation == TEE_HANDLE_NULL || (!srcData && srcLen))
		TEE_Panic(0);

	__utee_check_attr_in_annotation(params, paramCount);
	__utee_check_inout_annotation(destLen, sizeof(*destLen));

	if (!operation->key1)
		TEE_Panic(0);
	if (operation->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER)
		TEE_Panic(0);
	if (operation->info.mode != TEE_MODE_DECRYPT)
		TEE_Panic(0);

	__utee_from_attr(ua, params, paramCount);
	dl = *destLen;
	res = _utee_asymm_operate(operation->state, ua, paramCount, srcData,
				  srcLen, destData, &dl);
	*destLen = dl;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_SHORT_BUFFER &&
	    res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
				    const TEE_Attribute *params,
				    uint32_t paramCount, const void *digest,
				    uint32_t digestLen, void *signature,
				    uint32_t *signatureLen)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_attribute ua[paramCount];
	uint64_t sl = 0;

	if (operation == TEE_HANDLE_NULL || (!digest && digestLen))
		TEE_Panic(0);

	__utee_check_attr_in_annotation(params, paramCount);
	__utee_check_inout_annotation(signatureLen, sizeof(*signatureLen));

	if (!operation->key1)
		TEE_Panic(0);
	if (operation->info.operationClass !=
	    TEE_OPERATION_ASYMMETRIC_SIGNATURE)
		TEE_Panic(0);
	if (operation->info.mode != TEE_MODE_SIGN)
		TEE_Panic(0);

	__utee_from_attr(ua, params, paramCount);
	sl = *signatureLen;
	res = _utee_asymm_operate(operation->state, ua, paramCount, digest,
				  digestLen, signature, &sl);
	*signatureLen = sl;

	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
				      const TEE_Attribute *params,
				      uint32_t paramCount, const void *digest,
				      uint32_t digestLen,
				      const void *signature,
				      uint32_t signatureLen)
{
	TEE_Result res;
	struct utee_attribute ua[paramCount];

	if (operation == TEE_HANDLE_NULL ||
	    (digest == NULL && digestLen != 0) ||
	    (signature == NULL && signatureLen != 0))
		TEE_Panic(0);

	__utee_check_attr_in_annotation(params, paramCount);

	if (!operation->key1)
		TEE_Panic(0);
	if (operation->info.operationClass !=
	    TEE_OPERATION_ASYMMETRIC_SIGNATURE)
		TEE_Panic(0);
	if (operation->info.mode != TEE_MODE_VERIFY)
		TEE_Panic(0);

	__utee_from_attr(ua, params, paramCount);
	res = _utee_asymm_verify(operation->state, ua, paramCount, digest,
				 digestLen, signature, signatureLen);

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
	struct utee_attribute ua[paramCount];

	if (operation == TEE_HANDLE_NULL || derivedKey == 0)
		TEE_Panic(0);

	__utee_check_attr_in_annotation(params, paramCount);

	if (TEE_ALG_GET_CLASS(operation->info.algorithm) !=
	    TEE_OPERATION_KEY_DERIVATION)
		TEE_Panic(0);

	if (operation->info.operationClass != TEE_OPERATION_KEY_DERIVATION)
		TEE_Panic(0);
	if (!operation->key1)
		TEE_Panic(0);
	if (operation->info.mode != TEE_MODE_DERIVE)
		TEE_Panic(0);
	if ((operation->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0)
		TEE_Panic(0);

	res = _utee_cryp_obj_get_info((unsigned long)derivedKey, &key_info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if (key_info.objectType != TEE_TYPE_GENERIC_SECRET)
		TEE_Panic(0);
	if ((key_info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		TEE_Panic(0);

	__utee_from_attr(ua, params, paramCount);
	res = _utee_cryp_derive_key(operation->state, ua, paramCount,
				    (unsigned long)derivedKey);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

/* Cryptographic Operations API - Random Number Generation Functions */

void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen)
{
	TEE_Result res;

	res = _utee_cryp_random_number_generate(randomBuffer, randomBufferLen);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

int rand(void)
{
	int rc;

	TEE_GenerateRandom(&rc, sizeof(rc));

	/*
	 * RAND_MAX is the larges int, INT_MAX which is all bits but the
	 * highest bit set.
	 */
	return rc & RAND_MAX;
}

TEE_Result TEE_IsAlgorithmSupported(uint32_t alg, uint32_t element)
{
	if (IS_ENABLED(CFG_CRYPTO_AES)) {
		if (IS_ENABLED(CFG_CRYPTO_ECB)) {
			if (alg == TEE_ALG_AES_ECB_NOPAD)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CBC)) {
			if (alg == TEE_ALG_AES_CBC_NOPAD)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CTR)) {
			if (alg == TEE_ALG_AES_CTR)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CTS)) {
			if (alg == TEE_ALG_AES_CTS)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_XTS)) {
			if (alg == TEE_ALG_AES_XTS)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CBC_MAC)) {
			if (alg == TEE_ALG_AES_CBC_MAC_NOPAD ||
			    alg == TEE_ALG_AES_CBC_MAC_PKCS5)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CMAC)) {
			if (alg == TEE_ALG_AES_CMAC)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CCM)) {
			if (alg == TEE_ALG_AES_CCM)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_GCM)) {
			if (alg == TEE_ALG_AES_GCM)
				goto check_element_none;
		}
	}
	if (IS_ENABLED(CFG_CRYPTO_DES)) {
		if (IS_ENABLED(CFG_CRYPTO_ECB)) {
			if (alg == TEE_ALG_DES_ECB_NOPAD ||
			    alg == TEE_ALG_DES3_ECB_NOPAD)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CBC)) {
			if (alg == TEE_ALG_DES_CBC_NOPAD ||
			    alg == TEE_ALG_DES3_CBC_NOPAD)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CBC_MAC)) {
			if (alg == TEE_ALG_DES_CBC_MAC_NOPAD ||
			    alg == TEE_ALG_DES_CBC_MAC_PKCS5 ||
			    alg == TEE_ALG_DES3_CBC_MAC_NOPAD ||
			    alg == TEE_ALG_DES3_CBC_MAC_PKCS5)
				goto check_element_none;
		}
	}
	if (IS_ENABLED(CFG_CRYPTO_MD5)) {
		if (alg == TEE_ALG_MD5)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_SHA1)) {
		if (alg == TEE_ALG_SHA1)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_SHA224)) {
		if (alg == TEE_ALG_SHA224)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_SHA256)) {
		if (alg == TEE_ALG_SHA256)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_SHA384)) {
		if (alg == TEE_ALG_SHA384)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_SHA512)) {
		if (alg == TEE_ALG_SHA512)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_MD5) && IS_ENABLED(CFG_CRYPTO_SHA1)) {
		if (alg == TEE_ALG_MD5SHA1)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_HMAC)) {
		if (IS_ENABLED(CFG_CRYPTO_MD5)) {
			if (alg == TEE_ALG_HMAC_MD5)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA1)) {
			if (alg == TEE_ALG_HMAC_SHA1)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA224)) {
			if (alg == TEE_ALG_HMAC_SHA224)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA256)) {
			if (alg == TEE_ALG_HMAC_SHA256)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA384)) {
			if (alg == TEE_ALG_HMAC_SHA384)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA512)) {
			if (alg == TEE_ALG_HMAC_SHA512)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SM3)) {
			if (alg == TEE_ALG_HMAC_SM3)
				goto check_element_none;
		}
	}
	if (IS_ENABLED(CFG_CRYPTO_SM3)) {
		if (alg == TEE_ALG_SM3)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_SM4)) {
		if (IS_ENABLED(CFG_CRYPTO_ECB)) {
			if (alg == TEE_ALG_SM4_ECB_NOPAD)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CBC)) {
			if (alg == TEE_ALG_SM4_CBC_NOPAD)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_CTR)) {
			if (alg == TEE_ALG_SM4_CTR)
				goto check_element_none;
		}
	}
	if (IS_ENABLED(CFG_CRYPTO_RSA)) {
		if (IS_ENABLED(CFG_CRYPTO_MD5)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_MD5)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA1)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 ||
			    alg == TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 ||
			    alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_MD5) && IS_ENABLED(CFG_CRYPTO_SHA1)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_MD5SHA1)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA224)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_SHA224 ||
			    alg == TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 ||
			    alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA256)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 ||
			    alg == TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 ||
			    alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA384)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_SHA384 ||
			    alg == TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 ||
			    alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA512)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 ||
			    alg == TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 ||
			    alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_RSASSA_NA1)) {
			if (alg == TEE_ALG_RSASSA_PKCS1_V1_5)
				goto check_element_none;
		}
		if (alg == TEE_ALG_RSA_NOPAD)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_DSA)) {
		if (IS_ENABLED(CFG_CRYPTO_SHA1)) {
			if (alg == TEE_ALG_DSA_SHA1)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA224)) {
			if (alg == TEE_ALG_DSA_SHA224)
				goto check_element_none;
		}
		if (IS_ENABLED(CFG_CRYPTO_SHA256)) {
			if (alg == TEE_ALG_DSA_SHA256)
				goto check_element_none;
		}
	}
	if (IS_ENABLED(CFG_CRYPTO_DH)) {
		if (alg == TEE_ALG_DH_DERIVE_SHARED_SECRET)
			goto check_element_none;
	}
	if (IS_ENABLED(CFG_CRYPTO_ECC)) {
		if ((alg == TEE_ALG_ECDH_P192 || alg == TEE_ALG_ECDSA_P192) &&
		    element == TEE_ECC_CURVE_NIST_P192)
			return TEE_SUCCESS;
		if ((alg == TEE_ALG_ECDH_P224 || alg == TEE_ALG_ECDSA_P224) &&
		    element == TEE_ECC_CURVE_NIST_P224)
			return TEE_SUCCESS;
		if ((alg == TEE_ALG_ECDH_P256 || alg == TEE_ALG_ECDSA_P256) &&
		    element == TEE_ECC_CURVE_NIST_P256)
			return TEE_SUCCESS;
		if ((alg == TEE_ALG_ECDH_P384 || alg == TEE_ALG_ECDSA_P384) &&
		    element == TEE_ECC_CURVE_NIST_P384)
			return TEE_SUCCESS;
		if ((alg == TEE_ALG_ECDH_P521 || alg == TEE_ALG_ECDSA_P521) &&
		    element == TEE_ECC_CURVE_NIST_P521)
			return TEE_SUCCESS;
	}
	if (IS_ENABLED(CFG_CRYPTO_SM2_DSA)) {
		if (alg == TEE_ALG_SM2_DSA_SM3 && element == TEE_ECC_CURVE_SM2)
			return TEE_SUCCESS;
	}
	if (IS_ENABLED(CFG_CRYPTO_SM2_KEP)) {
		if (alg == TEE_ALG_SM2_KEP && element == TEE_ECC_CURVE_SM2)
			return TEE_SUCCESS;
	}
	if (IS_ENABLED(CFG_CRYPTO_SM2_PKE)) {
		if (alg == TEE_ALG_SM2_PKE && element == TEE_ECC_CURVE_SM2)
			return TEE_SUCCESS;
	}

	return TEE_ERROR_NOT_SUPPORTED;
check_element_none:
	if (element == TEE_CRYPTO_ELEMENT_NONE)
		return TEE_SUCCESS;
	return TEE_ERROR_NOT_SUPPORTED;
}
