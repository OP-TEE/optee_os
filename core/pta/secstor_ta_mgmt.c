// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <kernel/pseudo_ta.h>
#include <tee/tadb.h>
#include <pta_secstor_ta_mgmt.h>
#include <signed_hdr.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <crypto/crypto.h>
#include <tee/uuid.h>
#include <types_ext.h>
#include <utee_defines.h>

static TEE_Result check_install_conflict(const struct shdr_bootstrap_ta *bs_ta)
{
	TEE_Result res;
	struct tee_tadb_ta_read *ta;
	TEE_UUID uuid;
	const struct tee_tadb_property *prop;

	tee_uuid_from_octets(&uuid, bs_ta->uuid);
	res = tee_tadb_ta_open(&uuid, &ta);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	if (res)
		return res;

	prop = tee_tadb_ta_get_property(ta);
	if (prop->version > bs_ta->ta_version)
		res = TEE_ERROR_ACCESS_CONFLICT;

	tee_tadb_ta_close(ta);
	return res;
}

static TEE_Result install_ta(struct shdr *shdr, const uint8_t *nw,
			     size_t nw_size)
{
	TEE_Result res;
	struct tee_tadb_ta_write *ta;
	void *hash_ctx = NULL;
	size_t offs;
	const size_t buf_size = 2 * 4096;
	void *buf;
	struct tee_tadb_property property;
	struct shdr_bootstrap_ta bs_ta;

	if (shdr->img_type != SHDR_BOOTSTRAP_TA)
		return TEE_ERROR_SECURITY;

	if (nw_size < (sizeof(struct shdr_bootstrap_ta) + SHDR_GET_SIZE(shdr)))
		return TEE_ERROR_SECURITY;

	if (shdr->hash_size > buf_size)
		return TEE_ERROR_SECURITY;

	buf = malloc(buf_size);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Initialize a hash context and run the algorithm over the signed
	 * header (less the final file hash and its signature of course)
	 */
	res = crypto_hash_alloc_ctx(&hash_ctx,
				    TEE_DIGEST_HASH_TO_ALGO(shdr->algo));
	if (res)
		goto err;
	res = crypto_hash_init(hash_ctx);
	if (res)
		goto err_free_hash_ctx;
	res = crypto_hash_update(hash_ctx, (uint8_t *)shdr, sizeof(*shdr));
	if (res)
		goto err_free_hash_ctx;

	offs = SHDR_GET_SIZE(shdr);
	memcpy(&bs_ta, nw + offs, sizeof(bs_ta));

	/* Check that we're not downgrading a TA */
	res = check_install_conflict(&bs_ta);
	if (res)
		goto err_free_hash_ctx;

	res = crypto_hash_update(hash_ctx, (uint8_t *)&bs_ta, sizeof(bs_ta));
	if (res)
		goto err_free_hash_ctx;
	offs += sizeof(bs_ta);

	memset(&property, 0, sizeof(property));
	COMPILE_TIME_ASSERT(sizeof(property.uuid) == sizeof(bs_ta.uuid));
	tee_uuid_from_octets(&property.uuid, bs_ta.uuid);
	property.version = bs_ta.ta_version;
	property.custom_size = 0;
	property.bin_size = nw_size - offs;
	DMSG("Installing %pUl", (void *)&property.uuid);

	res = tee_tadb_ta_create(&property, &ta);
	if (res)
		goto err_free_hash_ctx;

	while (offs < nw_size) {
		size_t l = MIN(buf_size, nw_size - offs);

		memcpy(buf, nw + offs, l);
		res = crypto_hash_update(hash_ctx, buf, l);
		if (res)
			goto err_ta_finalize;
		res = tee_tadb_ta_write(ta, buf, l);
		if (res)
			goto err_ta_finalize;
		offs += l;
	}

	res = crypto_hash_final(hash_ctx, buf, shdr->hash_size);
	if (res)
		goto err_ta_finalize;
	if (consttime_memcmp(buf, SHDR_GET_HASH(shdr), shdr->hash_size)) {
		res = TEE_ERROR_SECURITY;
		goto err_ta_finalize;
	}

	crypto_hash_free_ctx(hash_ctx);
	free(buf);
	return tee_tadb_ta_close_and_commit(ta);

err_ta_finalize:
	tee_tadb_ta_close_and_delete(ta);
err_free_hash_ctx:
	crypto_hash_free_ctx(hash_ctx);
err:
	free(buf);
	return res;
}

static TEE_Result bootstrap(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	struct shdr *shdr;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	shdr = shdr_alloc_and_copy(params->memref.buffer, params->memref.size);
	if (!shdr)
		return TEE_ERROR_SECURITY;

	res = shdr_verify_signature(shdr);
	if (res)
		goto out;

	res = install_ta(shdr, params->memref.buffer, params->memref.size);
out:
	shdr_free(shdr);
	return res;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_SECSTOR_TA_MGMT_BOOTSTRAP:
		return bootstrap(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SECSTOR_TA_MGMT_UUID, .name = "secstor_ta_mgmt",
		   /*
		    * TA_FLAG_SINGLE_INSTANCE and TA_FLAG_MULTI_SESSION are
		    * current part of PTA_DEFAULT_FLAGS, but as this TA
		    * depends on those two flags we add them explicitly
		    * too.
		    */
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_SINGLE_INSTANCE |
			    TA_FLAG_MULTI_SESSION,
		   .invoke_command_entry_point = invoke_command);
