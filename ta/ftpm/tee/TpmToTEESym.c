// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 * Copyright (c) 2024, Linaro Limited
 */

#include "Tpm.h"
#include <tee_internal_api.h>
#include <stdint.h>
#include <string.h>

/*
 * TEE_SetKeyAES() - Set AES key.
 * @ks	pointer to space for storing the key schedule
 * @key	pointer to the key
 * @sz	length of the key in bytes
 *
 * There is no "finalize" function, so we can't allocate  the key schedule
 * here, because we could never free it.
 *
 * return 0 if ok, any other value otherwise
 */
int TEE_SetKeyAES(tpmKeyScheduleAES *ks, const uint8_t *key, uint16_t sz)
{
	if (sz == 16 || sz == 24 || sz == 32) {
		ks->keySizeInBytes = sz;
		memcpy(ks->key, key, sz);
		return 0;
	} else {
		return 1;
	}
}

/*
 * TEE_SetKeyTDES() - Set DES key.
 * @ks	pointer to space for storing the key schedule
 * @key	pointer to the key
 * @sz	length of the key in bytes
 *
 * There is no "finalize" function, so we can't allocate  the key schedule
 * here, because we could never free it.
 *
 * return 0 if ok, any other value otherwise
 */
int TEE_SetKeyTDES(tpmKeyScheduleTDES *ks, const uint8_t *key, uint16_t sz)
{
	if (sz == 16 || sz == 24) {
		ks->keySizeInBytes = sz;
		memcpy(ks->key, key, sz);
		return 0;
	} else {
		return 1;
	}
}

/*
 * TEE_SetKeySM4() - Set SM4 key.
 * @ks	pointer to space for storing the key schedule
 * @key	pointer to the key
 * @sz	length of the key in bytes
 *
 * return 0 if ok, any other value otherwise
 *
 * There is no "finalize" function, so we can't allocate  the key schedule
 * here, because we could never free it.
 */
int TEE_SetKeySM4(tpmKeyScheduleSM4 *ks, const uint8_t *key, uint16_t sz)
{
	if (sz == 16) {
		ks->keySizeInBytes = sz;
		memcpy(ks->key, key, sz);
		return 0;
	} else {
		return 1;
	}
}

/*
 * The functions calling this function can't return an error so neither can
 * this. In case of error we panic since the alternative is to carry out
 * the operation incorrectly.
 */
static void block_op(uint8_t *out, uint32_t algo, uint32_t mode,
		     size_t block_size, TEE_ObjectType obj_type,
		     const uint8_t *key, uint16_t keySizeInBytes,
		     const uint8_t *in)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t outlen = block_size;
	TEE_Attribute attr = {};

	res = TEE_AllocateTransientObject(obj_type, 8 * keySizeInBytes, &obj);
	if (res)
		TEE_Panic(res);

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keySizeInBytes);
	res = TEE_PopulateTransientObject(obj, &attr, 1);
	if (res)
		TEE_Panic(res);

	res = TEE_AllocateOperation(&op, algo, mode, 8 * keySizeInBytes);
	if (res)
		TEE_Panic(res);

	res = TEE_SetOperationKey(op, obj);
	if (res)
		TEE_Panic(res);

	TEE_CipherInit(op, 0, 0);
	outlen = block_size;
	res = TEE_CipherDoFinal(op, in, block_size, out, &outlen);
	if (res)
		TEE_Panic(res);

	TEE_FreeOperation(op);
	TEE_FreeTransientObject(obj);
}

void TEE_AESEncrypt(uint8_t *out, const tpmKeyScheduleAES *ks,
		    const uint8_t *in)
{
	block_op(out, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT, 16, TEE_TYPE_AES,
		 ks->key, ks->keySizeInBytes, in);
}

void TEE_AESDecrypt(uint8_t *out, const tpmKeyScheduleAES *ks,
		    const uint8_t *in)
{
	block_op(out, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_DECRYPT, 16, TEE_TYPE_AES,
		 ks->key, ks->keySizeInBytes, in);
}

void TEE_TDESEncrypt(uint8_t *out, const tpmKeyScheduleTDES *ks,
		     const uint8_t *in)
{
	block_op(out, TEE_ALG_DES3_ECB_NOPAD, TEE_MODE_ENCRYPT, 8,
		 TEE_TYPE_DES3, ks->key, ks->keySizeInBytes, in);
}

void TEE_TDESDecrypt(uint8_t *out, const tpmKeyScheduleTDES *ks,
		     const uint8_t *in)
{
	block_op(out, TEE_ALG_DES3_ECB_NOPAD, TEE_MODE_DECRYPT, 8,
		 TEE_TYPE_DES3, ks->key, ks->keySizeInBytes, in);
}

void TEE_SM4Encrypt(uint8_t *out, const tpmKeyScheduleSM4 *ks,
		    const uint8_t *in)
{
	block_op(out, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_ENCRYPT, 16, TEE_TYPE_SM4,
		 ks->key, ks->keySizeInBytes, in);
}

void TEE_SM4Decrypt(uint8_t *out, const tpmKeyScheduleSM4 *ks,
		    const uint8_t *in)
{
	block_op(out, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_DECRYPT, 16, TEE_TYPE_SM4,
		 ks->key, ks->keySizeInBytes, in);
}
