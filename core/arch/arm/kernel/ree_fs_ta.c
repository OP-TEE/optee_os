/*
 * Copyright (c) 2017, Linaro Limited
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
#include <assert.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/msg_param.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <optee_msg_supplicant.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/uuid.h>
#include <utee_defines.h>

#include "elf_load.h"

struct user_ta_store_handle {
	struct shdr *nw_ta; /* Non-secure (shared memory) */
	size_t nw_ta_size;
	uint64_t cookie;
	struct mobj *mobj;
	size_t offs;
	struct shdr *shdr; /* Verified secure copy of @nw_ta's signed header */
	void *hash_ctx;
	uint32_t hash_algo;
};

/*
 * Load a TA via RPC with UUID defined by input param @uuid. The virtual
 * address of the raw TA binary is received in out parameter @ta.
 */
static TEE_Result rpc_load(const TEE_UUID *uuid, struct shdr **ta,
			   uint64_t *cookie_ta, size_t *ta_size,
			   struct mobj **mobj)
{
	TEE_Result res;
	struct optee_msg_param params[2];
	uint64_t cta = 0;

	if (!uuid || !ta || !cookie_ta || !mobj || !ta_size)
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

	*mobj = thread_rpc_alloc_payload(params[1].u.tmem.size, &cta);
	if (!*mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ta = mobj_get_va(*mobj, 0);
	/* We don't expect NULL as thread_rpc_alloc_payload() was successful */
	assert(*ta);
	*cookie_ta = cta;
	*ta_size = params[1].u.tmem.size;

	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	tee_uuid_to_octets((void *)&params[0].u.value, uuid);
	msg_param_init_memparam(params + 1, *mobj, 0, params[1].u.tmem.size,
				cta, MSG_PARAM_MEM_DIR_OUT);

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_LOAD_TA, 2, params);
	if (res != TEE_SUCCESS)
		thread_rpc_free_payload(cta, *mobj);
	return res;
}

static TEE_Result ta_open(const TEE_UUID *uuid,
			  struct user_ta_store_handle **h)
{
	struct user_ta_store_handle *handle;
	struct shdr *shdr = NULL;
	struct mobj *mobj = NULL;
	void *hash_ctx = NULL;
	size_t hash_ctx_size;
	uint32_t hash_algo;
	struct shdr *ta = NULL;
	size_t ta_size = 0;
	uint64_t cookie = 0;
	TEE_Result res;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Request TA from tee-supplicant */
	res = rpc_load(uuid, &ta, &cookie, &ta_size, &mobj);
	if (res != TEE_SUCCESS)
		goto error;

	/* Make secure copy of signed header */
	shdr = shdr_alloc_and_copy(ta, ta_size);
	if (!shdr) {
		res = TEE_ERROR_SECURITY;
		goto error_free_payload;
	}

	/* Validate header signature */
	res = shdr_verify_signature(shdr);
	if (res != TEE_SUCCESS)
		goto error_free_payload;
	if (shdr->img_type != SHDR_TA) {
		res = TEE_ERROR_SECURITY;
		goto error_free_payload;
	}

	/*
	 * Initialize a hash context and run the algorithm over the signed
	 * header (less the final file hash and its signature of course)
	 */
	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	res = crypto_hash_get_ctx_size(hash_algo, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		goto error_free_payload;
	hash_ctx = malloc(hash_ctx_size);
	if (!hash_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_free_payload;
	}
	res = crypto_hash_init(hash_ctx, hash_algo);
	if (res != TEE_SUCCESS)
		goto error_free_payload;
	res = crypto_hash_update(hash_ctx, hash_algo, (uint8_t *)shdr,
				     sizeof(*shdr));
	if (res != TEE_SUCCESS)
		goto error_free_payload;

	if (ta_size != SHDR_GET_SIZE(shdr) + shdr->img_size) {
		res = TEE_ERROR_SECURITY;
		goto error_free_payload;
	}

	handle->nw_ta = ta;
	handle->nw_ta_size = ta_size;
	handle->cookie = cookie;
	handle->offs = SHDR_GET_SIZE(shdr);
	handle->hash_algo = hash_algo;
	handle->hash_ctx = hash_ctx;
	handle->shdr = shdr;
	handle->mobj = mobj;
	*h = handle;
	return TEE_SUCCESS;

error_free_payload:
	thread_rpc_free_payload(cookie, mobj);
error:
	free(hash_ctx);
	shdr_free(shdr);
	free(handle);
	return res;
}

static TEE_Result ta_get_size(const struct user_ta_store_handle *h,
			      size_t *size)
{
	*size = h->shdr->img_size;
	return TEE_SUCCESS;
}

static TEE_Result check_digest(struct user_ta_store_handle *h)
{
	void *digest = NULL;
	TEE_Result res;

	digest = malloc(h->shdr->hash_size);
	if (!digest)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = crypto_hash_final(h->hash_ctx, h->hash_algo, digest,
				    h->shdr->hash_size);
	if (res != TEE_SUCCESS) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	if (memcmp(digest, SHDR_GET_HASH(h->shdr), h->shdr->hash_size))
		res = TEE_ERROR_SECURITY;
out:
	free(digest);
	return res;
}

static TEE_Result ta_read(struct user_ta_store_handle *h, void *data,
			  size_t len)
{
	uint8_t *src = (uint8_t *)h->nw_ta + h->offs;
	uint8_t *dst = src;
	TEE_Result res;

	if (h->offs + len > h->nw_ta_size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (data) {
		dst = data; /* Hash secure buffer (shm might be modified) */
		memcpy(dst, src, len);
	}
	res = crypto_hash_update(h->hash_ctx, h->hash_algo, dst, len);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_SECURITY;
	h->offs += len;
	if (h->offs == h->nw_ta_size) {
		/*
		 * Last read: time to check if our digest matches the expected
		 * one (from the signed header)
		 */
		res = check_digest(h);
	}
	return res;
}

static void ta_close(struct user_ta_store_handle *h)
{
	if (!h)
		return;
	thread_rpc_free_payload(h->cookie, h->mobj);
	free(h->hash_ctx);
	free(h->shdr);
	free(h);
}

static struct user_ta_store_ops ops = {
	.description = "REE",
	.open = ta_open,
	.get_size = ta_get_size,
	.read = ta_read,
	.close = ta_close,
	.priority = 10,
};

static TEE_Result register_supplicant_user_ta(void)
{
	return tee_ta_register_ta_store(&ops);
}

service_init(register_supplicant_user_ta);
