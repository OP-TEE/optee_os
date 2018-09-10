// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <assert.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
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
			   size_t *ta_size, struct mobj **mobj)
{
	TEE_Result res;
	struct thread_param params[2];

	if (!uuid || !ta || !mobj || !ta_size)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(params, 0, sizeof(params));
	params[0].attr = THREAD_PARAM_ATTR_VALUE_IN;
	tee_uuid_to_octets((void *)&params[0].u.value, uuid);
	params[1].attr = THREAD_PARAM_ATTR_MEMREF_OUT;

	res = thread_rpc_cmd(OPTEE_RPC_CMD_LOAD_TA, 2, params);
	if (res != TEE_SUCCESS)
		return res;

	*mobj = thread_rpc_alloc_payload(params[1].u.memref.size);
	if (!*mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	if ((*mobj)->size < params[1].u.memref.size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	*ta = mobj_get_va(*mobj, 0);
	/* We don't expect NULL as thread_rpc_alloc_payload() was successful */
	assert(*ta);
	*ta_size = params[1].u.memref.size;

	params[0].attr = THREAD_PARAM_ATTR_VALUE_IN;
	tee_uuid_to_octets((void *)&params[0].u.value, uuid);
	params[1].attr = THREAD_PARAM_ATTR_MEMREF_OUT;
	params[1].u.memref.offs = 0;
	params[1].u.memref.mobj = *mobj;

	res = thread_rpc_cmd(OPTEE_RPC_CMD_LOAD_TA, 2, params);
exit:
	if (res != TEE_SUCCESS)
		thread_rpc_free_payload(*mobj);

	return res;
}

static TEE_Result ta_open(const TEE_UUID *uuid,
			  struct user_ta_store_handle **h)
{
	struct user_ta_store_handle *handle;
	struct shdr *shdr = NULL;
	struct mobj *mobj = NULL;
	void *hash_ctx = NULL;
	uint32_t hash_algo = 0;
	struct shdr *ta = NULL;
	size_t ta_size = 0;
	TEE_Result res;
	size_t offs;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Request TA from tee-supplicant */
	res = rpc_load(uuid, &ta, &ta_size, &mobj);
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
	if (shdr->img_type != SHDR_TA && shdr->img_type != SHDR_BOOTSTRAP_TA) {
		res = TEE_ERROR_SECURITY;
		goto error_free_payload;
	}

	/*
	 * Initialize a hash context and run the algorithm over the signed
	 * header (less the final file hash and its signature of course)
	 */
	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	res = crypto_hash_alloc_ctx(&hash_ctx, hash_algo);
	if (res != TEE_SUCCESS)
		goto error_free_payload;
	res = crypto_hash_init(hash_ctx, hash_algo);
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	res = crypto_hash_update(hash_ctx, hash_algo, (uint8_t *)shdr,
				     sizeof(*shdr));
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	offs = SHDR_GET_SIZE(shdr);

	if (shdr->img_type == SHDR_BOOTSTRAP_TA) {
		TEE_UUID bs_uuid;
		struct shdr_bootstrap_ta bs_hdr;

		if (ta_size < SHDR_GET_SIZE(shdr) + sizeof(bs_hdr))
			return TEE_ERROR_SECURITY;

		memcpy(&bs_hdr, ((uint8_t *)ta + offs), sizeof(bs_hdr));

		/*
		 * There's a check later that the UUID embedded inside the
		 * ELF is matching, but since we now have easy access to
		 * the expected uuid of the TA we check it a bit earlier
		 * here.
		 */
		tee_uuid_from_octets(&bs_uuid, bs_hdr.uuid);
		if (memcmp(&bs_uuid, uuid, sizeof(TEE_UUID))) {
			res = TEE_ERROR_SECURITY;
			goto error_free_hash;
		}

		res = crypto_hash_update(hash_ctx, hash_algo,
					 (uint8_t *)&bs_hdr, sizeof(bs_hdr));
		if (res != TEE_SUCCESS)
			goto error_free_hash;
		offs += sizeof(bs_hdr);
	}

	if (ta_size != offs + shdr->img_size) {
		res = TEE_ERROR_SECURITY;
		goto error_free_hash;
	}

	handle->nw_ta = ta;
	handle->nw_ta_size = ta_size;
	handle->offs = offs;
	handle->hash_algo = hash_algo;
	handle->hash_ctx = hash_ctx;
	handle->shdr = shdr;
	handle->mobj = mobj;
	*h = handle;
	return TEE_SUCCESS;

error_free_hash:
	crypto_hash_free_ctx(hash_ctx, hash_algo);
error_free_payload:
	thread_rpc_free_payload(mobj);
error:
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
	thread_rpc_free_payload(h->mobj);
	crypto_hash_free_ctx(h->hash_ctx, h->hash_algo);
	free(h->shdr);
	free(h);
}

TEE_TA_REGISTER_TA_STORE(9) = {
	.description = "REE",
	.open = ta_open,
	.get_size = ta_get_size,
	.read = ta_read,
	.close = ta_close,
};
