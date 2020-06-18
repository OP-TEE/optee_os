// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017-2020, Linaro Limited
 */
#include <printk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api.h>
#include <tee_api_types.h>
#include <tee_arith_internal.h>
#include <tee_internal_api_extensions.h>
#include <tee_isocket.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include <util.h>

#include "base64.h"
#include "string_ext.h"
#include "tee_api_private.h"

#define PROP_STR_MAX    80

#define PROP_ENUMERATOR_NOT_STARTED 0xffffffff

struct prop_enumerator {
	uint32_t idx;			/* current index */
	TEE_PropSetHandle prop_set;	/* part of TEE_PROPSET_xxx */
};

const struct user_ta_property tee_props[] = {
	{
		"gpd.tee.arith.maxBigIntSize",
		USER_TA_PROP_TYPE_U32,
		&(const uint32_t){CFG_TA_BIGNUM_MAX_BITS}
	},
	{
		"gpd.tee.sockets.version",
		USER_TA_PROP_TYPE_U32,
		&(const uint32_t){TEE_ISOCKET_VERSION}
	},
	{
		"gpd.tee.sockets.tcp.version",
		USER_TA_PROP_TYPE_U32,
		&(const uint32_t){TEE_ISOCKET_VERSION}
	},
};

static TEE_Result propset_get(TEE_PropSetHandle h,
			      const struct user_ta_property **eps,
			      size_t *eps_len)
{
	if (h == TEE_PROPSET_CURRENT_TA) {
		*eps = ta_props;
		*eps_len = ta_num_props;
	} else if (h == TEE_PROPSET_CURRENT_CLIENT) {
		*eps = NULL;
		*eps_len = 0;
	} else if (h == TEE_PROPSET_TEE_IMPLEMENTATION) {
		*eps = tee_props;
		*eps_len = ARRAY_SIZE(tee_props);
	} else {
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	return TEE_SUCCESS;
}

static TEE_Result propget_get_ext_prop(const struct user_ta_property *ep,
				       enum user_ta_prop_type *type,
				       void *buf, uint32_t *len)
{
	size_t l;

	*type = ep->type;
	switch (*type) {
	case USER_TA_PROP_TYPE_BOOL:
		l = sizeof(bool);
		break;
	case USER_TA_PROP_TYPE_U32:
		l = sizeof(uint32_t);
		break;
	case USER_TA_PROP_TYPE_UUID:
		l = sizeof(TEE_UUID);
		break;
	case USER_TA_PROP_TYPE_IDENTITY:
		l = sizeof(TEE_Identity);
		break;
	case USER_TA_PROP_TYPE_STRING:
		/* take the leading 0 into account */
		l = strlen(ep->value) + 1;
		break;
	case USER_TA_PROP_TYPE_BINARY_BLOCK:
		/*
		 * in case of TA property, a binary block is provided as a
		 * string, which is base64 encoded. We must first decode it,
		 * without taking into account the zero termination of the
		 * string
		 */
		l = *len;
		if (!_base64_dec(ep->value, strlen(ep->value), buf, &l) &&
		    l <= *len)
			return TEE_ERROR_GENERIC;
		if (*len < l) {
			*len = l;
			return TEE_ERROR_SHORT_BUFFER;
		}

		*len = l;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_GENERIC;
	}

	if (*len < l) {
		*len = l;
		return TEE_ERROR_SHORT_BUFFER;
	}

	*len = l;
	memcpy(buf, ep->value, l);
	return TEE_SUCCESS;
}

static bool is_propset_pseudo_handle(TEE_PropSetHandle h)
{
	return h == TEE_PROPSET_CURRENT_TA ||
	       h == TEE_PROPSET_CURRENT_CLIENT ||
	       h == TEE_PROPSET_TEE_IMPLEMENTATION;
}

static TEE_Result propget_get_property(TEE_PropSetHandle h, const char *name,
				       enum user_ta_prop_type *type,
				       void *buf, uint32_t *len)
{
	TEE_Result res;
	const struct user_ta_property *eps;
	size_t eps_len;
	uint32_t prop_type;
	uint32_t index;

	if (is_propset_pseudo_handle(h)) {
		size_t n;

		res = propset_get(h, &eps, &eps_len);
		if (res != TEE_SUCCESS)
			return res;

		for (n = 0; n < eps_len; n++) {
			if (!strcmp(name, eps[n].name))
				return propget_get_ext_prop(eps + n, type,
							    buf, len);
		}

		/* get the index from the name */
		res = _utee_get_property_name_to_index((unsigned long)h, name,
						       strlen(name) + 1,
						       &index);
		if (res != TEE_SUCCESS)
			return res;
		res = _utee_get_property((unsigned long)h, index, NULL, NULL,
					 buf, len, &prop_type);
	} else {
		struct prop_enumerator *pe = (struct prop_enumerator *)h;
		uint32_t idx = pe->idx;

		if (idx == PROP_ENUMERATOR_NOT_STARTED)
			return TEE_ERROR_ITEM_NOT_FOUND;

		res = propset_get(pe->prop_set, &eps, &eps_len);
		if (res != TEE_SUCCESS)
			return res;

		if (idx < eps_len)
			return propget_get_ext_prop(eps + idx, type, buf, len);
		idx -= eps_len;

		res = _utee_get_property((unsigned long)pe->prop_set, idx,
					 NULL, NULL, buf, len, &prop_type);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_ERROR_BAD_PARAMETERS;
	}

	*type = prop_type;
	return res;
}

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
				   const char *name, char *value,
				   uint32_t *value_len)
{
	TEE_Result res;
	size_t l;
	enum user_ta_prop_type type;
	void *tmp_buf = 0;
	uint32_t tmp_len;
	uint32_t uint32_val;
	bool bool_val;
	TEE_Identity *p_identity_val;

	if (is_propset_pseudo_handle(propsetOrEnumerator))
		__utee_check_instring_annotation(name);
	__utee_check_outstring_annotation(value, value_len);

	tmp_len = *value_len;
	if (tmp_len < sizeof(TEE_Identity))
		tmp_len = sizeof(TEE_Identity);
	tmp_buf = TEE_Malloc(tmp_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!tmp_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = propget_get_property(propsetOrEnumerator, name, &type,
				   tmp_buf, &tmp_len);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_SHORT_BUFFER) {
			if (type == USER_TA_PROP_TYPE_BINARY_BLOCK) {
				/*
				 * in this case, we must enlarge the buffer
				 * with the size of the of the base64 encoded
				 * see base64_enc() function
				 */
				tmp_len = _base64_enc_len(tmp_len);
			}
			*value_len = tmp_len;
		}
		goto out;
	}

	switch (type) {
	case USER_TA_PROP_TYPE_BOOL:
		bool_val = *((bool *)tmp_buf);
		l = strlcpy(value, (bool_val ? "true" : "false"), *value_len);
		break;

	case USER_TA_PROP_TYPE_U32:
		uint32_val = *((uint32_t *)tmp_buf);
		l = snprintf(value, *value_len, "%u", uint32_val);
		break;

	case USER_TA_PROP_TYPE_UUID:
		l = snprintk(value, *value_len, "%pUl", tmp_buf);
		break;

	case USER_TA_PROP_TYPE_IDENTITY:
		p_identity_val = ((TEE_Identity *)tmp_buf);
		l = snprintk(value, *value_len, "%u:%pUl",
			     p_identity_val->login,
			     (void *)(&(p_identity_val->uuid)));
		break;

	case USER_TA_PROP_TYPE_STRING:
		l = strlcpy(value, tmp_buf, *value_len);
		break;

	case USER_TA_PROP_TYPE_BINARY_BLOCK:
		l = *value_len;	/* l includes the zero-termination */
		if (!_base64_enc(tmp_buf, tmp_len, value, &l) &&
		    l <= *value_len) {
			res = TEE_ERROR_GENERIC;
			goto out;
		}
		l--;	/* remove the zero-termination that is added later */
		break;

	default:
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	l++;	/* include zero termination */

	if (l > *value_len)
		res = TEE_ERROR_SHORT_BUFFER;
	*value_len = l;

out:
	if (tmp_buf)
		TEE_Free(tmp_buf);
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(0);

	return res;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
				 const char *name, bool *value)
{
	TEE_Result res;
	enum user_ta_prop_type type;
	uint32_t bool_len = sizeof(bool);

	if (is_propset_pseudo_handle(propsetOrEnumerator))
		__utee_check_instring_annotation(name);
	__utee_check_out_annotation(value, sizeof(*value));

	type = USER_TA_PROP_TYPE_BOOL;
	res = propget_get_property(propsetOrEnumerator, name, &type,
				   value, &bool_len);
	if (type != USER_TA_PROP_TYPE_BOOL)
		res = TEE_ERROR_BAD_FORMAT;
	if (res != TEE_SUCCESS)
		goto out;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_BAD_FORMAT)
		TEE_Panic(0);

	return res;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
				const char *name, uint32_t *value)
{
	TEE_Result res;
	enum user_ta_prop_type type;
	uint32_t uint32_len = sizeof(uint32_t);

	if (is_propset_pseudo_handle(propsetOrEnumerator))
		__utee_check_instring_annotation(name);
	__utee_check_out_annotation(value, sizeof(*value));

	type = USER_TA_PROP_TYPE_U32;
	res = propget_get_property(propsetOrEnumerator, name, &type,
				   value, &uint32_len);
	if (type != USER_TA_PROP_TYPE_U32)
		res = TEE_ERROR_BAD_FORMAT;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_BAD_FORMAT)
		TEE_Panic(0);

	return res;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
					const char *name, void *value,
					uint32_t *value_len)
{
	TEE_Result res;
	enum user_ta_prop_type type;

	if (is_propset_pseudo_handle(propsetOrEnumerator))
		__utee_check_instring_annotation(name);
	__utee_check_outbuf_annotation(value, value_len);

	type = USER_TA_PROP_TYPE_BINARY_BLOCK;
	res = propget_get_property(propsetOrEnumerator, name, &type,
				   value, value_len);
	if (type != USER_TA_PROP_TYPE_BINARY_BLOCK)
		res = TEE_ERROR_BAD_FORMAT;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_BAD_FORMAT &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(0);

	return res;
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
				 const char *name, TEE_UUID *value)
{
	TEE_Result res;
	enum user_ta_prop_type type;
	uint32_t uuid_len = sizeof(TEE_UUID);

	if (is_propset_pseudo_handle(propsetOrEnumerator))
		__utee_check_instring_annotation(name);
	__utee_check_out_annotation(value, sizeof(*value));

	type = USER_TA_PROP_TYPE_UUID;
	res = propget_get_property(propsetOrEnumerator, name, &type,
				   value, &uuid_len);
	if (type != USER_TA_PROP_TYPE_UUID)
		res = TEE_ERROR_BAD_FORMAT;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_BAD_FORMAT)
		TEE_Panic(0);

	return res;
}

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
				     const char *name, TEE_Identity *value)
{
	TEE_Result res;
	enum user_ta_prop_type type;
	uint32_t identity_len = sizeof(TEE_Identity);

	if (is_propset_pseudo_handle(propsetOrEnumerator))
		__utee_check_instring_annotation(name);
	__utee_check_out_annotation(value, sizeof(*value));

	type = USER_TA_PROP_TYPE_IDENTITY;
	res = propget_get_property(propsetOrEnumerator, name, &type,
				   value, &identity_len);
	if (type != USER_TA_PROP_TYPE_IDENTITY)
		res = TEE_ERROR_BAD_FORMAT;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_BAD_FORMAT)
		TEE_Panic(0);

	return res;
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
	TEE_Result res;
	struct prop_enumerator *pe;

	__utee_check_out_annotation(enumerator, sizeof(*enumerator));

	pe = TEE_Malloc(sizeof(struct prop_enumerator),
			TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (pe == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	*enumerator = (TEE_PropSetHandle) pe;
	TEE_ResetPropertyEnumerator(*enumerator);

	goto out;

err:
	if (res == TEE_ERROR_OUT_OF_MEMORY)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator)
{
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;

	pe->idx = PROP_ENUMERATOR_NOT_STARTED;
}

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator)
{
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;

	TEE_Free(pe);
}

void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator,
				 TEE_PropSetHandle propSet)
{
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;

	if (!pe)
		return;

	pe->idx = 0;
	pe->prop_set = propSet;
}

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator,
			       void *name, uint32_t *name_len)
{
	TEE_Result res;
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;
	const struct user_ta_property *eps;
	size_t eps_len;
	const char *str;
	size_t bufferlen;

	if (!pe) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	__utee_check_outstring_annotation(name, name_len);

	bufferlen = *name_len;
	res = propset_get(pe->prop_set, &eps, &eps_len);
	if (res != TEE_SUCCESS)
		goto err;

	if (pe->idx < eps_len) {
		str = eps[pe->idx].name;
		bufferlen = strlcpy(name, str, *name_len) + 1;
		if (bufferlen > *name_len)
			res = TEE_ERROR_SHORT_BUFFER;
		*name_len = bufferlen;
	} else {
		res = _utee_get_property((unsigned long)pe->prop_set,
					 pe->idx - eps_len, name, name_len,
					 NULL, NULL, NULL);
		if (res != TEE_SUCCESS)
			goto err;
	}

err:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(0);
	return res;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
	TEE_Result res;
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;
	uint32_t next_idx;
	const struct user_ta_property *eps;
	size_t eps_len;

	if (!pe) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (pe->idx == PROP_ENUMERATOR_NOT_STARTED) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	res = propset_get(pe->prop_set, &eps, &eps_len);
	if (res != TEE_SUCCESS)
		goto out;

	next_idx = pe->idx + 1;
	pe->idx = next_idx;
	if (next_idx < eps_len)
		res = TEE_SUCCESS;
	else
		res = _utee_get_property((unsigned long)pe->prop_set,
					 next_idx - eps_len, NULL, NULL, NULL,
					 NULL, NULL);

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND)
		TEE_Panic(0);
	return res;
}
