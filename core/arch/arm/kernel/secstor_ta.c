// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <tee/tadb.h>
#include <kernel/ts_store.h>
#include <kernel/user_ta.h>
#include <initcall.h>

static TEE_Result secstor_ta_open(const TEE_UUID *uuid,
				  struct ts_store_handle **handle)
{
	TEE_Result res;
	struct tee_tadb_ta_read *ta;
	size_t l;
	const struct tee_tadb_property *prop;

	res = tee_tadb_ta_open(uuid, &ta);
	if (res)
		return res;
	prop = tee_tadb_ta_get_property(ta);

	l = prop->custom_size;
	res = tee_tadb_ta_read(ta, NULL, &l);
	if (res)
		goto err;
	if (l != prop->custom_size) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto err;
	}

	*handle = (struct ts_store_handle *)ta;

	return TEE_SUCCESS;
err:
	tee_tadb_ta_close(ta);
	return res;
}

static TEE_Result secstor_ta_get_size(const struct ts_store_handle *h,
				      size_t *size)
{
	struct tee_tadb_ta_read *ta = (struct tee_tadb_ta_read *)h;
	const struct tee_tadb_property *prop = tee_tadb_ta_get_property(ta);

	*size = prop->bin_size;

	return TEE_SUCCESS;
}

static TEE_Result secstor_ta_get_tag(const struct ts_store_handle *h,
				     uint8_t *tag, unsigned int *tag_len)
{
	return tee_tadb_get_tag((struct tee_tadb_ta_read *)h, tag, tag_len);
}

static TEE_Result secstor_ta_read(struct ts_store_handle *h, void *data,
				  size_t len)
{
	struct tee_tadb_ta_read *ta = (struct tee_tadb_ta_read *)h;
	size_t l = len;
	TEE_Result res = tee_tadb_ta_read(ta, data, &l);

	if (res)
		return res;
	if (l != len)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static void secstor_ta_close(struct ts_store_handle *h)
{
	struct tee_tadb_ta_read *ta = (struct tee_tadb_ta_read *)h;

	tee_tadb_ta_close(ta);
}

REGISTER_TA_STORE(4) = {
	.description = "Secure Storage TA",
	.open = secstor_ta_open,
	.get_size = secstor_ta_get_size,
	.get_tag = secstor_ta_get_tag,
	.read = secstor_ta_read,
	.close = secstor_ta_close,
};
