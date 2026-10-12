// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 RICSec
 */

#include <compiler.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <pta_veraison_attestation.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_storage.h>
#include <trace.h>
#include <utee_defines.h>

#ifdef CFG_NXP_CAAM_ECC_DRV
#include <drivers/caam_extension.h>
#endif

#include "key.h"
#include "sign.h"

#ifdef CFG_VERAISON_ATTESTATION_PTA_TEST_KEY

TEE_Result key_get(const struct signing_key **skey)
{
	*skey = sign_test_key();

	return TEE_SUCCESS;
}

TEE_Result key_import(const uint8_t *pub_x __unused,
		      const uint8_t *pub_y __unused,
		      const uint8_t *priv __unused,
		      const struct signing_key **skey __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#else /* CFG_VERAISON_ATTESTATION_PTA_TEST_KEY */

#define KEY_SIZE SIGNING_KEY_COORD_SIZE
#define KEY_SIZE_BIT (KEY_SIZE * 8)
#define PUBLIC_KEY_SIZE (2 * KEY_SIZE)
/* The stored object: public key X and Y followed by the private key */
#define STORED_KEY_MAX_SIZE (PUBLIC_KEY_SIZE + SIGNING_KEY_PRIV_MAX_SIZE)

static TEE_UUID pta_uuid = PTA_VERAISON_ATTESTATION_UUID;

/* Name of the key object in the private storage of the PTA */
static const uint8_t key_obj_id[] = "iak";

/* The stored key, read once and kept for the lifetime of the PTA */
static struct signing_key stored_key;
static bool stored_key_valid;
static struct mutex key_mutex = MUTEX_INITIALIZER;

static TEE_Result storage_get(uint32_t flags, enum tee_pobj_usage usage,
			      struct tee_pobj **po)
{
	const struct tee_file_operations *fops = NULL;

	fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	if (!fops)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return tee_pobj_get(&pta_uuid, (void *)key_obj_id,
			    sizeof(key_obj_id) - 1, flags, usage, fops, po);
}

static TEE_Result storage_read(uint8_t *data, size_t *len)
{
	struct tee_file_handle *fh = NULL;
	struct tee_pobj *po = NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t file_size = 0;

	res = storage_get(TEE_DATA_FLAG_ACCESS_READ, TEE_POBJ_USAGE_OPEN, &po);
	if (res)
		return res;

	res = po->fops->open(po, &file_size, &fh);
	if (res)
		goto out;

	res = po->fops->read(fh, 0, data, NULL, len);

	po->fops->close(&fh);
out:
	tee_pobj_release(po);

	return res;
}

/*
 * Write the object in one go, and only if there is none yet: the key is
 * never replaced, so the store never has to swap an object in place.
 */
static TEE_Result storage_write(const uint8_t *data, size_t len)
{
	struct tee_file_handle *fh = NULL;
	struct tee_pobj *po = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = storage_get(TEE_DATA_FLAG_ACCESS_WRITE, TEE_POBJ_USAGE_CREATE,
			  &po);
	if (res)
		return res;

	res = po->fops->create(po, false, NULL, 0, NULL, 0, data, NULL, len,
			       &fh);
	if (!res) {
		po->fops->close(&fh);
		tee_pobj_create_final(po);
	}

	tee_pobj_release(po);

	return res;
}

static TEE_Result storage_remove(void)
{
	struct tee_pobj *po = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = storage_get(TEE_DATA_FLAG_ACCESS_WRITE_META, TEE_POBJ_USAGE_OPEN,
			  &po);
	if (res)
		return res;

	res = po->fops->remove(po);

	tee_pobj_release(po);

	return res;
}

static TEE_Result key_load(struct signing_key *skey)
{
	uint8_t buf[STORED_KEY_MAX_SIZE] = { };
	size_t len = sizeof(buf);
	TEE_Result res = TEE_SUCCESS;

	res = storage_read(buf, &len);
	if (res)
		goto out;

	if (len <= PUBLIC_KEY_SIZE) {
		EMSG("Stored key too short");
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}

	memcpy(skey->pub_x, buf, KEY_SIZE);
	memcpy(skey->pub_y, buf + KEY_SIZE, KEY_SIZE);
	skey->priv_len = len - PUBLIC_KEY_SIZE;
	memcpy(skey->priv, buf + PUBLIC_KEY_SIZE, skey->priv_len);
out:
	memzero_explicit(buf, sizeof(buf));

	return res;
}

static TEE_Result key_save(const struct signing_key *skey)
{
	uint8_t buf[STORED_KEY_MAX_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;

	memcpy(buf, skey->pub_x, KEY_SIZE);
	memcpy(buf + KEY_SIZE, skey->pub_y, KEY_SIZE);
	memcpy(buf + PUBLIC_KEY_SIZE, skey->priv, skey->priv_len);

	res = storage_write(buf, PUBLIC_KEY_SIZE + skey->priv_len);

	memzero_explicit(buf, sizeof(buf));

	return res;
}

/* Export a bignum as a fixed-size big-endian field, zero padded */
static TEE_Result export_coord(struct bignum *bn, uint8_t *out, size_t size)
{
	size_t len = crypto_bignum_num_bytes(bn);

	if (len > size)
		return TEE_ERROR_GENERIC;

	memset(out, 0, size);
	crypto_bignum_bn2bin(bn, out + size - len);

	return TEE_SUCCESS;
}

static TEE_Result key_generate_new(struct signing_key *skey)
{
	struct ecc_keypair key = { };
	TEE_Result res = TEE_SUCCESS;
	size_t priv_len = 0;

	res = crypto_acipher_alloc_ecc_keypair(&key, TEE_TYPE_ECDSA_KEYPAIR,
					       KEY_SIZE_BIT);
	if (res)
		return res;
	key.curve = TEE_ECC_CURVE_NIST_P256;

	/*
	 * With the CAAM ECC driver the private key is generated as a black
	 * key and key.d holds its serialized form, a blob, so the plain key
	 * never exists outside the CAAM.
	 */
	res = crypto_acipher_gen_ecc_key(&key, KEY_SIZE_BIT);
	if (res)
		goto out;

	priv_len = crypto_bignum_num_bytes(key.d);
	if (!priv_len || priv_len > SIGNING_KEY_PRIV_MAX_SIZE) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(skey, 0, sizeof(*skey));
	crypto_bignum_bn2bin(key.d, skey->priv);
	skey->priv_len = priv_len;
	res = export_coord(key.x, skey->pub_x, KEY_SIZE);
	if (res)
		goto out;
	res = export_coord(key.y, skey->pub_y, KEY_SIZE);
out:
	crypto_bignum_free(&key.d);
	crypto_bignum_free(&key.x);
	crypto_bignum_free(&key.y);
	if (res)
		memzero_explicit(skey, sizeof(*skey));

	return res;
}

/*
 * Load the stored key into the cache. Called with key_mutex held.
 * Returns TEE_ERROR_ITEM_NOT_FOUND when there is no key, after discarding
 * a key object that cannot be read.
 */
static TEE_Result key_cache(void)
{
	TEE_Result res = TEE_SUCCESS;

	if (stored_key_valid)
		return TEE_SUCCESS;

	res = key_load(&stored_key);
	if (res == TEE_ERROR_CORRUPT_OBJECT) {
		EMSG("Stored signing key unusable, discarding it");
		res = storage_remove();
		if (!res)
			res = TEE_ERROR_ITEM_NOT_FOUND;
	}
	if (res) {
		memzero_explicit(&stored_key, sizeof(stored_key));
		return res;
	}

	stored_key_valid = true;

	return TEE_SUCCESS;
}

TEE_Result key_get(const struct signing_key **skey)
{
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&key_mutex);

	res = key_cache();
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("No signing key yet, generating one");
		res = key_generate_new(&stored_key);
		if (!res)
			res = key_save(&stored_key);
		if (res)
			memzero_explicit(&stored_key, sizeof(stored_key));
		else
			stored_key_valid = true;
	}
	if (res)
		goto out;

	*skey = &stored_key;
out:
	mutex_unlock(&key_mutex);

	return res;
}

TEE_Result key_import(const uint8_t *pub_x, const uint8_t *pub_y,
		      const uint8_t *priv, const struct signing_key **skey)
{
	static const uint8_t check_msg[] = "veraison_attestation key import";
	struct signing_key new_key = { };
	uint8_t sig[2 * KEY_SIZE] = { };
	size_t sig_len = sizeof(sig);
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&key_mutex);

	/* The key is installed once: refuse when there already is one */
	res = key_cache();
	if (!res)
		res = TEE_ERROR_ACCESS_CONFLICT;
	if (res != TEE_ERROR_ITEM_NOT_FOUND)
		goto out;

	memcpy(new_key.pub_x, pub_x, KEY_SIZE);
	memcpy(new_key.pub_y, pub_y, KEY_SIZE);
#ifdef CFG_NXP_CAAM_ECC_DRV
	/* Keep it as a CAAM black key, like a generated key */
	new_key.priv_len = sizeof(new_key.priv);
	res = caam_key_wrap_black(priv, KEY_SIZE, new_key.priv,
				  &new_key.priv_len);
	if (res)
		goto out;
#else
	memcpy(new_key.priv, priv, KEY_SIZE);
	new_key.priv_len = KEY_SIZE;
#endif

	/* Only a matching pair signs and verifies */
	res = sign_ecdsa_sha256(&new_key, check_msg, sizeof(check_msg), sig,
				&sig_len);
	if (res) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = key_save(&new_key);
	if (res)
		goto out;

	stored_key = new_key;
	stored_key_valid = true;
	*skey = &stored_key;
out:
	memzero_explicit(&new_key, sizeof(new_key));
	mutex_unlock(&key_mutex);

	return res;
}

#endif /* CFG_VERAISON_ATTESTATION_PTA_TEST_KEY */
