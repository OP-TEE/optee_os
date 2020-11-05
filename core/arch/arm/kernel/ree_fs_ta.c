// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */

/*
 * Security properties of REE-FS TAs
 * =================================
 *
 * Authentication only
 * -------------------
 *
 * Required security properties:
 * 1. Authentication and non-repudiation of a TA to Service Provider (SP).
 * 2. Integrity of a TA.
 *
 * To satisfy (1) and (2), SP needs to sign TA and OP-TEE core needs to verify
 * the signature using SP public key with computed hash of the TA.
 *
 * Authentication along with Confidentiality
 * -----------------------------------------
 *
 * Required security properties:
 * 1. Authentication and non-repudiation of a TA to Service Provider (SP).
 * 2. Confidentiality of a TA.
 * 3. Integrity of an encrypted TA blob.
 *
 * To satisfy (1), SP needs to sign plain TA and OP-TEE core needs to verify the
 * signature using SP public key with computed hash of the TA.
 *
 * To satisfy (2) and (3), SP needs to do authenticated encryption of TA and
 * OP-TEE core needs to do authenticated decryption of TA to retrieve its
 * contents. Here encryption provides the confidentiality of TA and MAC tag
 * provides the integrity of encrypted TA blob.
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/thread.h>
#include <kernel/ts_store.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_storage.h>
#include <tee/tee_ta_enc_manager.h>
#include <tee/uuid.h>
#include <utee_defines.h>

struct ree_fs_ta_handle {
	struct shdr *nw_ta; /* Non-secure (shared memory) */
	size_t nw_ta_size;
	struct mobj *mobj;
	size_t offs;
	struct shdr *shdr; /* Verified secure copy of @nw_ta's signed header */
	void *hash_ctx;
	void *enc_ctx;
	struct shdr_bootstrap_ta *bs_hdr;
	struct shdr_encrypted_ta *ehdr;
};

struct ta_ver_db_hdr {
	uint32_t db_version;
	uint32_t nb_entries;
};

static const char ta_ver_db_obj_id[] = "ta_ver.db";
static struct mutex ta_ver_db_mutex = MUTEX_INITIALIZER;

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
				 struct ts_store_handle **h)
{
	struct ree_fs_ta_handle *handle;
	struct shdr *shdr = NULL;
	struct mobj *mobj = NULL;
	void *hash_ctx = NULL;
	struct shdr *ta = NULL;
	size_t ta_size = 0;
	TEE_Result res;
	size_t offs;
	struct shdr_bootstrap_ta *bs_hdr = NULL;
	struct shdr_encrypted_ta *ehdr = NULL;

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
	if (shdr->img_type != SHDR_TA && shdr->img_type != SHDR_BOOTSTRAP_TA &&
	    shdr->img_type != SHDR_ENCRYPTED_TA) {
		res = TEE_ERROR_SECURITY;
		goto error_free_payload;
	}

	/*
	 * Initialize a hash context and run the algorithm over the signed
	 * header (less the final file hash and its signature of course)
	 */
	res = crypto_hash_alloc_ctx(&hash_ctx,
				    TEE_DIGEST_HASH_TO_ALGO(shdr->algo));
	if (res != TEE_SUCCESS)
		goto error_free_payload;
	res = crypto_hash_init(hash_ctx);
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	res = crypto_hash_update(hash_ctx, (uint8_t *)shdr, sizeof(*shdr));
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	offs = SHDR_GET_SIZE(shdr);

	if (shdr->img_type == SHDR_BOOTSTRAP_TA ||
	    shdr->img_type == SHDR_ENCRYPTED_TA) {
		TEE_UUID bs_uuid;

		if (ta_size < SHDR_GET_SIZE(shdr) + sizeof(*bs_hdr)) {
			res = TEE_ERROR_SECURITY;
			goto error_free_hash;
		}

		bs_hdr = malloc(sizeof(*bs_hdr));
		if (!bs_hdr) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto error_free_hash;
		}

		memcpy(bs_hdr, (uint8_t *)ta + offs, sizeof(*bs_hdr));

		/*
		 * There's a check later that the UUID embedded inside the
		 * ELF is matching, but since we now have easy access to
		 * the expected uuid of the TA we check it a bit earlier
		 * here.
		 */
		tee_uuid_from_octets(&bs_uuid, bs_hdr->uuid);
		if (memcmp(&bs_uuid, uuid, sizeof(TEE_UUID))) {
			res = TEE_ERROR_SECURITY;
			goto error_free_hash;
		}

		res = crypto_hash_update(hash_ctx, (uint8_t *)bs_hdr,
					 sizeof(*bs_hdr));
		if (res != TEE_SUCCESS)
			goto error_free_hash;
		offs += sizeof(*bs_hdr);
		handle->bs_hdr = bs_hdr;
	}

	if (shdr->img_type == SHDR_ENCRYPTED_TA) {
		struct shdr_encrypted_ta img_ehdr;

		if (ta_size < SHDR_GET_SIZE(shdr) +
		    sizeof(struct shdr_bootstrap_ta) + sizeof(img_ehdr)) {
			res = TEE_ERROR_SECURITY;
			goto error_free_hash;
		}

		memcpy(&img_ehdr, ((uint8_t *)ta + offs), sizeof(img_ehdr));

		ehdr = malloc(SHDR_ENC_GET_SIZE(&img_ehdr));
		if (!ehdr) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto error_free_hash;
		}

		memcpy(ehdr, ((uint8_t *)ta + offs),
		       SHDR_ENC_GET_SIZE(&img_ehdr));

		res = crypto_hash_update(hash_ctx, (uint8_t *)ehdr,
					 SHDR_ENC_GET_SIZE(ehdr));
		if (res != TEE_SUCCESS)
			goto error_free_hash;

		res = tee_ta_decrypt_init(&handle->enc_ctx, ehdr,
					  shdr->img_size);
		if (res != TEE_SUCCESS)
			goto error_free_hash;

		offs += SHDR_ENC_GET_SIZE(ehdr);
		handle->ehdr = ehdr;
	}

	if (ta_size != offs + shdr->img_size) {
		res = TEE_ERROR_SECURITY;
		goto error_free_hash;
	}

	handle->nw_ta = ta;
	handle->nw_ta_size = ta_size;
	handle->offs = offs;
	handle->hash_ctx = hash_ctx;
	handle->shdr = shdr;
	handle->mobj = mobj;
	*h = (struct ts_store_handle *)handle;
	return TEE_SUCCESS;

error_free_hash:
	crypto_hash_free_ctx(hash_ctx);
error_free_payload:
	thread_rpc_free_payload(mobj);
error:
	free(ehdr);
	free(bs_hdr);
	shdr_free(shdr);
	free(handle);
	return res;
}

static TEE_Result ree_fs_ta_get_size(const struct ts_store_handle *h,
				     size_t *size)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	*size = handle->shdr->img_size;
	return TEE_SUCCESS;
}

static TEE_Result ree_fs_ta_get_tag(const struct ts_store_handle *h,
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
	res = crypto_hash_final(h->hash_ctx, digest, h->shdr->hash_size);
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

static TEE_Result check_update_version(struct shdr_bootstrap_ta *hdr)
{
	struct shdr_bootstrap_ta hdr_entry = { };
	const struct tee_file_operations *ops = NULL;
	struct tee_file_handle *fh = NULL;
	TEE_Result res = TEE_SUCCESS;
	bool entry_found = false;
	size_t len = 0;
	unsigned int i = 0;
	struct ta_ver_db_hdr db_hdr = { };
	struct tee_pobj pobj = {
		.obj_id = (void *)ta_ver_db_obj_id,
		.obj_id_len = sizeof(ta_ver_db_obj_id)
	};

	mutex_lock(&ta_ver_db_mutex);
	ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	res = ops->open(&pobj, NULL, &fh);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		goto out;

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = ops->create(&pobj, false, NULL, 0, NULL, 0, NULL, 0, &fh);
		if (res != TEE_SUCCESS)
			goto out;

		res = ops->write(fh, 0, &db_hdr, sizeof(db_hdr));
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		len = sizeof(db_hdr);

		res = ops->read(fh, 0, &db_hdr, &len);
		if (res != TEE_SUCCESS) {
			goto out;
		} else if (len != sizeof(db_hdr)) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}
	}

	for (i = 0; i < db_hdr.nb_entries; i++) {
		len = sizeof(hdr_entry);

		res = ops->read(fh, sizeof(db_hdr) + (i * len), &hdr_entry,
				&len);
		if (res != TEE_SUCCESS) {
			goto out;
		} else if (len != sizeof(hdr_entry)) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		if (!memcmp(hdr->uuid, hdr_entry.uuid, sizeof(TEE_UUID))) {
			entry_found = true;
			break;
		}
	}

	if (entry_found) {
		if (hdr_entry.ta_version > hdr->ta_version) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto out;
		} else if (hdr_entry.ta_version < hdr->ta_version) {
			len = sizeof(*hdr);
			res = ops->write(fh, sizeof(db_hdr) + (i * len), hdr,
					 len);
			if (res != TEE_SUCCESS)
				goto out;
		}
	} else {
		len = sizeof(*hdr);
		res = ops->write(fh, sizeof(db_hdr) + (db_hdr.nb_entries * len),
				 hdr, len);
		if (res != TEE_SUCCESS)
			goto out;

		db_hdr.nb_entries++;
		res = ops->write(fh, 0, &db_hdr, sizeof(db_hdr));
		if (res != TEE_SUCCESS)
			goto out;
	}

out:
	ops->close(&fh);
	mutex_unlock(&ta_ver_db_mutex);
	return res;
}

static TEE_Result ree_fs_ta_read(struct ts_store_handle *h, void *data,
				 size_t len)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	uint8_t *src = (uint8_t *)handle->nw_ta + handle->offs;
	size_t next_offs = 0;
	uint8_t *dst = src;
	TEE_Result res = TEE_SUCCESS;

	if (ADD_OVERFLOW(handle->offs, len, &next_offs) ||
	    next_offs > handle->nw_ta_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (handle->shdr->img_type == SHDR_ENCRYPTED_TA) {
		if (data) {
			dst = data; /* Hash secure buffer */
			res = tee_ta_decrypt_update(handle->enc_ctx, dst, src,
						    len);
			if (res != TEE_SUCCESS)
				return TEE_ERROR_SECURITY;
		} else {
			size_t num_bytes = 0;
			size_t b_size = MIN(1024U, len);
			uint8_t *b = malloc(b_size);

			if (!b)
				return TEE_ERROR_OUT_OF_MEMORY;

			dst = NULL;
			while (num_bytes < len) {
				size_t n = MIN(b_size, len - num_bytes);

				res = tee_ta_decrypt_update(handle->enc_ctx, b,
							    src + num_bytes, n);
				if (res)
					break;
				num_bytes += n;

				res = crypto_hash_update(handle->hash_ctx, b,
							 n);
				if (res)
					break;
			}

			free(b);
			if (res != TEE_SUCCESS)
				return TEE_ERROR_SECURITY;
		}
	} else if (data) {
		dst = data; /* Hash secure buffer (shm might be modified) */
		memcpy(dst, src, len);
	}

	if (dst) {
		res = crypto_hash_update(handle->hash_ctx, dst, len);
		if (res != TEE_SUCCESS)
			return TEE_ERROR_SECURITY;
	}

	handle->offs = next_offs;
	if (handle->offs == handle->nw_ta_size) {
		if (handle->shdr->img_type == SHDR_ENCRYPTED_TA) {
			/*
			 * Last read: time to finalize authenticated
			 * decryption.
			 */
			res = tee_ta_decrypt_final(handle->enc_ctx,
						   handle->ehdr, NULL, NULL, 0);
			if (res != TEE_SUCCESS)
				return TEE_ERROR_SECURITY;
		}
		/*
		 * Last read: time to check if our digest matches the expected
		 * one (from the signed header)
		 */
		res = check_digest(handle);
		if (res != TEE_SUCCESS)
			return res;

		if (handle->bs_hdr)
			res = check_update_version(handle->bs_hdr);
	}
	return res;
}

static void ree_fs_ta_close(struct ts_store_handle *h)
{
	struct ree_fs_ta_handle *handle = (struct ree_fs_ta_handle *)h;

	if (!handle)
		return;
	thread_rpc_free_payload(handle->mobj);
	crypto_hash_free_ctx(handle->hash_ctx);
	free(handle->shdr);
	free(handle->ehdr);
	free(handle->bs_hdr);
	free(handle);
}

#ifndef CFG_REE_FS_TA_BUFFERED
REGISTER_TA_STORE(9) = {
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
	struct ts_store_handle *h; /* Note: a REE FS TA store handle */
	size_t ta_size;
	tee_mm_entry_t *mm;
	uint8_t *buf;
	size_t offs;
	uint8_t *tag;
	unsigned int tag_len;
};

static TEE_Result buf_ta_open(const TEE_UUID *uuid,
			      struct ts_store_handle **h)
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
	*h = (struct ts_store_handle *)handle;
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

static TEE_Result buf_ta_get_size(const struct ts_store_handle *h,
				  size_t *size)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;

	*size = handle->ta_size;
	return TEE_SUCCESS;
}

static TEE_Result buf_ta_read(struct ts_store_handle *h, void *data,
			      size_t len)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;
	uint8_t *src = handle->buf + handle->offs;
	size_t next_offs = 0;

	if (ADD_OVERFLOW(handle->offs, len, &next_offs) ||
	    next_offs > handle->ta_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (data)
		memcpy(data, src, len);
	handle->offs = next_offs;
	return TEE_SUCCESS;
}

static TEE_Result buf_ta_get_tag(const struct ts_store_handle *h,
				 uint8_t *tag, unsigned int *tag_len)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;

	*tag_len = handle->tag_len;
	if (!tag || *tag_len < handle->tag_len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(tag, handle->tag, handle->tag_len);

	return TEE_SUCCESS;
}

static void buf_ta_close(struct ts_store_handle *h)
{
	struct buf_ree_fs_ta_handle *handle = (struct buf_ree_fs_ta_handle *)h;

	if (!handle)
		return;
	tee_mm_free(handle->mm);
	free(handle->tag);
	free(handle);
}

REGISTER_TA_STORE(9) = {
	.description = "REE [buffered]",
	.open = buf_ta_open,
	.get_size = buf_ta_get_size,
	.get_tag = buf_ta_get_tag,
	.read = buf_ta_read,
	.close = buf_ta_close,
};

#endif /* CFG_REE_FS_TA_BUFFERED */
