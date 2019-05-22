// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <assert.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/uuid.h>
#include <utee_defines.h>

#include "elf_load.h"

struct ree_fs_ta_handle {
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

static TEE_Result ree_fs_ta_open(const TEE_UUID *uuid,
				 struct user_ta_store_handle **h)
{
	struct ree_fs_ta_handle *handle;
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

		if (ta_size < SHDR_GET_SIZE(shdr) + sizeof(bs_hdr)) {
			res = TEE_ERROR_SECURITY;
			goto error_free_hash;
		}

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
	*h = (struct user_ta_store_handle *)handle;
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

static TEE_Result ree_fs_ta_get_size(const struct user_ta_store_handle *h,
				     size_t *size)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	*size = handle->shdr->img_size;
	return TEE_SUCCESS;
}

static TEE_Result ree_fs_ta_get_tag(const struct user_ta_store_handle *h,
				    uint8_t *tag, unsigned int *tag_len)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	if (!tag || *tag_len < handle->shdr->hash_size) {
		*tag_len = handle->shdr->hash_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*tag_len = handle->shdr->hash_size;

	memcpy(tag, SHDR_GET_HASH(handle->shdr), handle->shdr->hash_size);

	return TEE_SUCCESS;
}

static TEE_Result check_digest(struct ree_fs_ta_handle *h)
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

static TEE_Result ree_fs_ta_read(struct user_ta_store_handle *h, void *data,
				 size_t len)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	uint8_t *src = (uint8_t *)handle->nw_ta + handle->offs;
	uint8_t *dst = src;
	TEE_Result res;

	if (handle->offs + len > handle->nw_ta_size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (data) {
		dst = data; /* Hash secure buffer (shm might be modified) */
		memcpy(dst, src, len);
	}
	res = crypto_hash_update(handle->hash_ctx, handle->hash_algo, dst, len);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_SECURITY;
	handle->offs += len;
	if (handle->offs == handle->nw_ta_size) {
		/*
		 * Last read: time to check if our digest matches the expected
		 * one (from the signed header)
		 */
		res = check_digest(handle);
	}
	return res;
}

static void ree_fs_ta_close(struct user_ta_store_handle *h)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	if (!handle)
		return;
	thread_rpc_free_payload(handle->mobj);
	crypto_hash_free_ctx(handle->hash_ctx, handle->hash_algo);
	free(handle->shdr);
	free(handle);
}

#ifndef CFG_REE_FS_TA_BUFFERED
TEE_TA_REGISTER_TA_STORE(9) = {
	.description = "REE",
	.open = ree_fs_ta_open,
	.get_size = ree_fs_ta_get_size,
	.get_tag = ree_fs_ta_get_tag,
	.read = ree_fs_ta_read,
	.close = ree_fs_ta_close,
};
#endif

#ifdef CFG_REE_FS_TA_BUFFERED

/*
 * This is a wrapper around the "REE FS" TA store.
 * The whole TA/library is read into a temporary buffer during .open(). This
 * allows the binary to be authenticated before any data is read and processed
 * by the upper layer (ELF loader).
 */

struct buf_ree_fs_ta_handle {
	struct user_ta_store_handle *h; /* Note: a REE FS TA store handle */
	size_t ta_size;
	tee_mm_entry_t *mm;
	uint8_t *buf;
	size_t offs;
	uint8_t *tag;
	unsigned int tag_len;
};

static TEE_Result buf_ta_open(const TEE_UUID *uuid,
			      struct user_ta_store_handle **h)
{
	struct buf_ree_fs_ta_handle *handle = NULL;
	TEE_Result res = TEE_SUCCESS;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = ree_fs_ta_open(uuid, &handle->h);
	if (res)
		goto err2;
	res = ree_fs_ta_get_size(handle->h, &handle->ta_size);
	if (res)
		goto err;

	res = ree_fs_ta_get_tag(handle->h, NULL, &handle->tag_len);
	if (res != TEE_ERROR_SHORT_BUFFER) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}
	handle->tag = malloc(handle->tag_len);
	if (!handle->tag) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	res = ree_fs_ta_get_tag(handle->h, handle->tag, &handle->tag_len);
	if (res)
		goto err;

	handle->mm = tee_mm_alloc(&tee_mm_sec_ddr, handle->ta_size);
	if (!handle->mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	handle->buf = phys_to_virt(tee_mm_get_smem(handle->mm),
				   MEM_AREA_TA_RAM);
	if (!handle->buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	res = ree_fs_ta_read(handle->h, handle->buf, handle->ta_size);
	if (res)
		goto err;
	*h = (struct user_ta_store_handle *)handle;
err:
	ree_fs_ta_close(handle->h);
err2:
	if (res) {
		tee_mm_free(handle->mm);
		free(handle->tag);
		free(handle);
	}
	return res;
}

static TEE_Result buf_ta_get_size(const struct user_ta_store_handle *h,
				  size_t *size)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;

	*size = handle->ta_size;
	return TEE_SUCCESS;
}

static TEE_Result buf_ta_read(struct user_ta_store_handle *h, void *data,
			      size_t len)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;
	uint8_t *src = handle->buf + handle->offs;

	if (handle->offs + len > handle->ta_size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (data)
		memcpy(data, src, len);
	handle->offs += len;
	return TEE_SUCCESS;
}

static TEE_Result buf_ta_get_tag(const struct user_ta_store_handle *h,
				 uint8_t *tag, unsigned int *tag_len)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;

	*tag_len = handle->tag_len;
	if (!tag || *tag_len < handle->tag_len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(tag, handle->tag, handle->tag_len);

	return TEE_SUCCESS;
}

static void buf_ta_close(struct user_ta_store_handle *h)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;

	if (!handle)
		return;
	tee_mm_free(handle->mm);
	free(handle->tag);
	free(handle);
}

TEE_TA_REGISTER_TA_STORE(9) = {
	.description = "REE [buffered]",
	.open = buf_ta_open,
	.get_size = buf_ta_get_size,
	.get_tag = buf_ta_get_tag,
	.read = buf_ta_read,
	.close = buf_ta_close,
};

#endif /* CFG_REE_FS_TA_BUFFERED */
