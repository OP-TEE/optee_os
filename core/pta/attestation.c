// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_store.h>
#include <mm/file.h>
#include <pta_attestation.h>
#include <stdlib.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <tee/uuid.h>
#include <utee_defines.h>

#define PTA_NAME "attestation.pta"

#define MAX_KEY_SIZE 4096

static TEE_UUID pta_uuid = PTA_ATTESTATION_UUID;

static struct rsa_keypair *key;

static const uint8_t key_file_name[] = "key";

static TEE_Result allocate_key(void)
{
	assert(!key);

	key = calloc(sizeof(*key), 1);
	if (!key)
		return TEE_ERROR_OUT_OF_MEMORY;

	COMPILE_TIME_ASSERT(CFG_ATTESTATION_PTA_KEY_SIZE <= MAX_KEY_SIZE);
	return crypto_acipher_alloc_rsa_keypair(key, MAX_KEY_SIZE);
}

static void free_key(void)
{
	crypto_acipher_free_rsa_keypair(key);
	free(key);
	key = NULL;
}

static TEE_Result generate_key(void)
{
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(65537);
	TEE_Result res = TEE_ERROR_GENERIC;

	res = allocate_key();
	if (res)
		return res;

	crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key->e);

	/*
	 * For security reasons, the RSA modulus size has to be at least the
	 * size of the data to be signed.
	 */
	DMSG("Generating %u bit RSA key pair", CFG_ATTESTATION_PTA_KEY_SIZE);
	COMPILE_TIME_ASSERT(CFG_ATTESTATION_PTA_KEY_SIZE >=
			    TEE_SHA256_HASH_SIZE);
	res = crypto_acipher_gen_rsa_key(key, CFG_ATTESTATION_PTA_KEY_SIZE);
	if (res)
		free_key();

	return res;
}

/*
 * Return values:
 * > 0 : Number of bytes written to buf
 *   0 : @sz too large (> UINT16_MAX) or @buf_sz too small
 */
static size_t serialize_bignum(uint8_t *buf, size_t buf_sz, struct bignum *bn)
{
	uint8_t *p = buf;
	size_t sz = crypto_bignum_num_bytes(bn);
	uint16_t val = TEE_U16_TO_BIG_ENDIAN(sz);
	size_t total_sz = sizeof(val) + sz;

	if (sz > UINT16_MAX || total_sz > buf_sz)
		return 0;

	memcpy(p, &val, sizeof(val));
	p += sizeof(val);

	crypto_bignum_bn2bin(bn, p);

	return total_sz;
}

static TEE_Result serialize_key(uint8_t **buf, size_t *size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *p = NULL;
	size_t max_sz = 0;
	size_t e_sz = 0;
	size_t d_sz = 0;
	size_t n_sz = 0;
	size_t sz = 0;

	assert(key);

	e_sz = crypto_bignum_num_bytes(key->e);
	d_sz = crypto_bignum_num_bytes(key->d);
	n_sz = crypto_bignum_num_bytes(key->n);
	if (e_sz > UINT16_MAX || d_sz > UINT16_MAX || n_sz > UINT16_MAX)
		return TEE_ERROR_GENERIC;

	max_sz = e_sz + d_sz + n_sz + 3 * sizeof(uint16_t);
	p = calloc(max_sz, 1);
	if (!p)
		return TEE_ERROR_OUT_OF_MEMORY;
	*buf = p;
	*size = max_sz;

	sz = serialize_bignum(p, max_sz, key->e);
	if (!sz)
		goto err;
	p += sz;
	max_sz -= sz;
	sz = serialize_bignum(p, max_sz, key->d);
	if (!sz)
		goto err;
	p += sz;
	max_sz -= sz;
	sz = serialize_bignum(p, max_sz, key->n);
	if (!sz)
		goto err;
	max_sz -= sz;
	assert(!max_sz);

	return TEE_SUCCESS;
err:
	free(p);
	*buf = NULL;
	*size = 0;
	return res;
}

static size_t deserialize_bignum(uint8_t *buf, size_t max_sz, struct bignum *bn)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *p = buf;
	uint16_t val = 0;
	size_t sz = 0;

	if (max_sz < sizeof(val))
		return 0;

	memcpy(&val, p, sizeof(val));
	sz = TEE_U16_FROM_BIG_ENDIAN(val);
	p += sizeof(val);
	max_sz -= sizeof(val);
	if (max_sz < sz)
		return 0;

	res = crypto_bignum_bin2bn(p, sz, bn);
	if (res)
		return 0;

	return sizeof(val) + sz;
}

static TEE_Result deserialize_key(uint8_t *buf, size_t buf_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *p = buf;
	size_t sz = 0;

	res = allocate_key();
	if (res)
		goto out;

	sz = deserialize_bignum(p, buf_sz, key->e);
	if (!sz)
		goto out;
	p += sz;
	buf_sz -= sz;
	sz = deserialize_bignum(p, buf_sz, key->d);
	if (!sz)
		goto out;
	p += sz;
	buf_sz -= sz;
	sz = deserialize_bignum(p, buf_sz, key->n);
	if (!sz)
		goto out;
	buf_sz -= sz;
	assert(!buf_sz);
out:
	return res;
}

static TEE_Result sec_storage_obj_read(TEE_UUID *uuid, uint32_t storage_id,
				       const uint8_t *obj_id,
				       size_t obj_id_len,
				       uint8_t *data, size_t *len,
				       size_t offset, uint32_t flags)
{
	const struct tee_file_operations *fops = NULL;
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct tee_file_handle *fh = NULL;
	struct tee_pobj *po = NULL;
	size_t file_size = 0;
	size_t read_len = 0;

	fops = tee_svc_storage_file_ops(storage_id);
	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (obj_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_pobj_get(uuid, (void *)obj_id, obj_id_len, flags, false, fops,
			   &po);
	if (res)
		return res;

	res = po->fops->open(po, &file_size, &fh);
	if (res)
		goto out;

	read_len = *len;
	res = po->fops->read(fh, offset, data, &read_len);
	if (res == TEE_ERROR_CORRUPT_OBJECT) {
		EMSG("Object corrupt");
		po->fops->remove(po);
	} else if (!res) {
		*len = read_len;
	}

	po->fops->close(&fh);
out:
	tee_pobj_release(po);

	return res;
}

static TEE_Result sec_storage_obj_write(TEE_UUID *uuid, uint32_t storage_id,
					const uint8_t *obj_id,
					size_t obj_id_len,
					const uint8_t *data, size_t len,
					size_t offset, uint32_t flags)

{
	const struct tee_file_operations *fops = NULL;
	struct tee_file_handle *fh = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct tee_pobj *po = NULL;

	fops = tee_svc_storage_file_ops(storage_id);
	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (obj_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_pobj_get(uuid, (void *)obj_id, obj_id_len, flags, false,
			   fops, &po);
	if (res)
		return res;

	res = po->fops->open(po, NULL, &fh);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = po->fops->create(po, false, NULL, 0, NULL, 0, NULL, 0,
				       &fh);
	if (!res) {
		res = po->fops->write(fh, offset, data, len);
		po->fops->close(&fh);
	}

	tee_pobj_release(po);

	return res;
}

static TEE_Result load_key(void)
{
	/*
	 * Serialized key pair is 3 bignums (e, p and n) plus their sizes
	 * encoded as uint16_t. e is 65537 so it needs only 3 bytes.
	 */
	size_t size = 3 + 2 * MAX_KEY_SIZE / 8 + 3 * sizeof(uint16_t);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *buf;

	buf = calloc(size, 1);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	DMSG("Loading RSA key pair from secure storage");
	res = sec_storage_obj_read(&pta_uuid, TEE_STORAGE_PRIVATE,
				   key_file_name, sizeof(key_file_name) - 1,
				   buf, &size, 0, TEE_DATA_FLAG_ACCESS_READ);
	if (res)
		goto out;
	DMSG("Read %zu bytes", size);
	res = deserialize_key(buf, size);
	if (!res)
		DMSG("Loaded %zu bit key pair", crypto_bignum_num_bits(key->n));

out:
	free(buf);
	return res;
}

static TEE_Result write_key(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *buf = NULL;
	size_t size = 0;

	DMSG("Saving key pair");
	res = serialize_key(&buf, &size);
	if (res)
		return res;

	res = sec_storage_obj_write(&pta_uuid, TEE_STORAGE_PRIVATE,
				    key_file_name, sizeof(key_file_name) - 1,
				    buf, size, 0, TEE_DATA_FLAG_ACCESS_WRITE);
	if (!res)
		DMSG("Wrote %zu bytes", size);
	free(buf);
	return res;
}

static TEE_Result init_key(void)
{
	TEE_Result res = TEE_SUCCESS;

	if (!key) {
		res = load_key();
		if (res) {
			res = generate_key();
			if (res)
				return res;
			res = write_key();
			if (res)
				return res;
		}
	}
	return res;
}

static TEE_Result hash_binary(const TEE_UUID *uuid, uint8_t *hash)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	unsigned int tag_len = FILE_TAG_SIZE;
	const struct ts_store_ops *ops = NULL;
	struct ts_store_handle *h = NULL;

	SCATTERED_ARRAY_FOREACH(ops, ta_stores, struct ts_store_ops) {
		res = ops->open(uuid, &h);
		if (!res)
			break;  /* TA found */
	}
	if (res)
		return res;

	/*
	 * Output hash size is assumed to be the same size as the file tag
	 * size which is the size of the digest in the TA shdr. If one or the
	 * other changes, additional hashing will be needed.
	 */
	COMPILE_TIME_ASSERT(FILE_TAG_SIZE == TEE_SHA256_HASH_SIZE);
	assert(ops);
	res = ops->get_tag(h, hash, &tag_len);
	if (res)
		goto out;

	DMSG("TA %pUl hash:", uuid);
	DHEXDUMP(hash, TEE_SHA256_HASH_SIZE);
out:
	ops->close(h);
	return res;
}

static TEE_Result digest_nonce_and_hash(uint8_t *digest, uint8_t *nonce,
					size_t nonce_sz, uint8_t *hash)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	if (nonce) {
		res = crypto_hash_update(ctx, nonce, nonce_sz);
		if (res)
			goto out;
	}
	res = crypto_hash_update(ctx, hash, TEE_SHA256_HASH_SIZE);
	if (res)
		goto out;
	res = crypto_hash_final(ctx, digest, TEE_SHA256_HASH_SIZE);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result sign_digest(uint8_t *sig, size_t sig_len,
			      const uint8_t *digest)
{
	return crypto_acipher_rsassa_sign(TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
					  key,
					  TEE_SHA256_HASH_SIZE, /* salt len */
					  digest, TEE_SHA256_HASH_SIZE,
					  sig, &sig_len);
}

static TEE_Result cmd_hash_ta(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { };
	TEE_UUID *uuid = params[0].memref.buffer;
	size_t uuid_sz = params[0].memref.size;
	uint8_t *nonce = params[1].memref.buffer;
	size_t nonce_sz = params[1].memref.size;
	uint8_t *out = params[2].memref.buffer;
	size_t out_sz = params[2].memref.size;
	size_t min_out_sz = 0;
	TEE_Result res = TEE_SUCCESS;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (uuid_sz != sizeof(*uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!out && out_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	res = init_key();
	if (res)
		return res;

	min_out_sz = TEE_SHA256_HASH_SIZE + crypto_bignum_num_bytes(key->n);
	if (out_sz < min_out_sz) {
		params[2].memref.size = min_out_sz;
		return TEE_ERROR_SHORT_BUFFER;
	}
	params[2].memref.size = min_out_sz;

	/*
	 * out = [ hash | sig(sha256(nonce | hash)) ]
	 *         ^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^
	 *          32B                modulus size
	 */

	res = hash_binary(uuid, out);
	if (res)
		return res;
	res = digest_nonce_and_hash(digest, nonce, nonce_sz, out);
	if (res)
		return res;
	return sign_digest(out + TEE_SHA256_HASH_SIZE,
			   out_sz - TEE_SHA256_HASH_SIZE, digest);
}

static TEE_Result cmd_get_pubkey(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *e = params[0].memref.buffer;
	uint32_t *e_out_sz = &params[0].memref.size;
	uint8_t *n = params[1].memref.buffer;
	uint32_t *n_out_sz = &params[1].memref.size;
	size_t sz = 0;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = init_key();
	if (res)
		return res;

	sz = crypto_bignum_num_bytes(key->e);
	if (*e_out_sz >= sz)
		crypto_bignum_bn2bin(key->e, e);
	else
		res = TEE_ERROR_SHORT_BUFFER;
	*e_out_sz = sz;

	sz = crypto_bignum_num_bytes(key->n);
	if (*n_out_sz >= sz)
		crypto_bignum_bn2bin(key->n, n);
	else
		res = TEE_ERROR_SHORT_BUFFER;
	*n_out_sz = sz;

	return res;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_ATTESTATION_HASH_TA:
		return cmd_hash_ta(param_types, params);
	case PTA_ATTESTATION_GET_PUBKEY:
		return cmd_get_pubkey(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
