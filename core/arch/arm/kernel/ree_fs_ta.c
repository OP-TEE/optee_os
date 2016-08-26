/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
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

#include <compiler.h>
#include <initcall.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <optee_msg_supplicant.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <string.h>
#include <ta_pub_key.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc_storage.h>
#include <tee/uuid.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#include "elf_common.h"
#include "elf_load.h"

static TEE_Result check_shdr(struct shdr *shdr)
{
	struct rsa_public_key key;
	TEE_Result res;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	size_t hash_size;

	if (shdr->magic != SHDR_MAGIC || shdr->img_type != SHDR_TA)
		return TEE_ERROR_SECURITY;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != TEE_MAIN_ALGO_RSA)
		return TEE_ERROR_SECURITY;

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(shdr->algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		return res;
	if (hash_size != shdr->hash_size)
		return TEE_ERROR_SECURITY;

	if (!crypto_ops.acipher.alloc_rsa_public_key ||
	    !crypto_ops.acipher.free_rsa_public_key ||
	    !crypto_ops.acipher.rsassa_verify ||
	    !crypto_ops.bignum.bin2bn)
		return TEE_ERROR_NOT_SUPPORTED;

	res = crypto_ops.acipher.alloc_rsa_public_key(&key, shdr->sig_size);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.bignum.bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_ops.bignum.bin2bn(ta_pub_key_modulus,
				       ta_pub_key_modulus_size, key.n);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.acipher.rsassa_verify(shdr->algo, &key, -1,
				SHDR_GET_HASH(shdr), shdr->hash_size,
				SHDR_GET_SIG(shdr), shdr->sig_size);
out:
	crypto_ops.acipher.free_rsa_public_key(&key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}

static TEE_Result ree_fs_ta_get_file_size(const TEE_UUID *uuid, size_t *size)
{
	TEE_Result res;
	struct optee_msg_param params[2];

	if (!uuid || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(params, 0, sizeof(params));
	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	tee_uuid_to_octets((void *)&params[0].u.value, uuid);
	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[1].u.tmem.buf_ptr = 0;
	params[1].u.tmem.size = 0;
	params[1].u.tmem.shm_ref = 0;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_LOAD_TA, 2, params);
	if (res != TEE_SUCCESS)
		return res;

	*size = params[1].u.tmem.size;

	return res;
}

static TEE_Result ree_fs_ta_load_file(const TEE_UUID *uuid, void *ta_file,
				      size_t ta_size)
{
	TEE_Result res;
	struct optee_msg_param params[2];
	void *ta;
	paddr_t phta = 0;
	uint64_t cta = 0;

	if (!uuid || !ta_file)
		return TEE_ERROR_BAD_PARAMETERS;

	thread_rpc_alloc_payload(ta_size, &phta, &cta);
	if (!phta)
		return TEE_ERROR_OUT_OF_MEMORY;

	ta = phys_to_virt(phta, MEM_AREA_NSEC_SHM);
	if (!ta) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(params, 0, sizeof(params));
	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	tee_uuid_to_octets((void *)&params[0].u.value, uuid);
	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[1].u.tmem.size = ta_size;
	params[1].u.tmem.buf_ptr = phta;
	params[1].u.tmem.shm_ref = cta;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_LOAD_TA, 2, params);
	if (res == TEE_SUCCESS)
		memcpy(ta_file, ta, ta_size);
out:
	thread_rpc_free_payload(cta);

	return res;
}

static TEE_Result ree_fs_ta_get_elf_size(const TEE_UUID *uuid __unused,
					 const void *ta_file, size_t file_size,
					 size_t *elf_size)
{
	if (!ta_file)
		return TEE_ERROR_BAD_PARAMETERS;

	*elf_size = file_size;
	return TEE_SUCCESS;
}

static TEE_Result ree_fs_ta_verify_and_decrypt(const TEE_UUID *uuid,
					       void *ta_elf,
					       const void *ta_file,
					       size_t file_size)
{
	struct shdr *shdr;
	uint8_t *nwdata;
	size_t nwdata_len;
	size_t hash_ctx_size;
	void *hash_ctx = NULL;
	uint32_t hash_algo;
	void *digest = NULL;
	TEE_Result res;

	(void)uuid;
	if (!ta_file || !ta_elf)
		return TEE_ERROR_BAD_PARAMETERS;

	shdr = (struct shdr *)ta_file;
	res = check_shdr(shdr);
	if (res != TEE_SUCCESS)
		return res;

	nwdata = (uint8_t *)ta_file + SHDR_GET_SIZE(shdr);
	nwdata_len = shdr->img_size;

	if ((nwdata_len + SHDR_GET_SIZE(shdr)) != file_size)
		return TEE_ERROR_SECURITY;

	if (!crypto_ops.hash.get_ctx_size || !crypto_ops.hash.init ||
			!crypto_ops.hash.update || !crypto_ops.hash.final) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		return res;
	}

	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	res = crypto_ops.hash.get_ctx_size(hash_algo, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		goto out;
	hash_ctx = malloc(hash_ctx_size);
	if (!hash_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = crypto_ops.hash.init(hash_ctx, hash_algo);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_ops.hash.update(hash_ctx, hash_algo,
			(uint8_t *)shdr, sizeof(struct shdr));
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.hash.update(hash_ctx, hash_algo,
			nwdata, nwdata_len);
	if (res != TEE_SUCCESS)
		goto out;

	digest = malloc(shdr->hash_size);
	if (!digest) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = crypto_ops.hash.final(hash_ctx, hash_algo, digest,
			shdr->hash_size);
	if (res != TEE_SUCCESS)
		goto out;

	if (memcmp(digest, SHDR_GET_HASH(shdr), shdr->hash_size) != 0) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	memcpy(ta_elf, (void *)nwdata, nwdata_len);
out:
	free(digest);
	free(hash_ctx);

	return res;
}

struct tee_ta_load_ops ree_fs_ta_load_ops = {
	.get_file_size = ree_fs_ta_get_file_size,
	.load_file = ree_fs_ta_load_file,
};

struct tee_ta_decryption_ops ree_fs_ta_decrytion_ops = {
	.get_elf_size = ree_fs_ta_get_elf_size,
	.verify_and_decrypt = ree_fs_ta_verify_and_decrypt,
};

static TEE_Result ree_fs_ta_init(void)
{
	DMSG("Registering load methods for REE FS TAs");

	tee_ta_register_load_ops(&ree_fs_ta_load_ops);
	tee_ta_register_decryption_ops(&ree_fs_ta_decrytion_ops);

	return TEE_SUCCESS;
}

service_init(ree_fs_ta_init);
