/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <tee_api.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <user_ta_header.h>
#include <tee_internal_api_extensions.h>
#include <tee_arith_internal.h>
#include <util.h>
#include <utee_syscalls.h>

#include "string_ext.h"
#include "base64.h"

#define PROP_STR_MAX    80

#define PROP_ENUMERATOR_NOT_STARTED 0xffffffff

struct prop_enumerator {
	uint32_t idx;			/* current index */
	TEE_PropSetHandle prop_set;	/* part of TEE_PROPSET_xxx */
};

struct prop_value {
	enum user_ta_prop_type type;
	union {
		uint32_t bool_val;
		uint32_t int_val;
		TEE_UUID uuid_val;
		TEE_Identity identity_val;
		char str_val[PROP_STR_MAX];
	} u;
};

const struct user_ta_property tee_props[] = {
	{
		"gpd.tee.arith.maxBigIntSize",
		USER_TA_PROP_TYPE_U32,
		&(const uint32_t){TEE_MAX_NUMBER_OF_SUPPORTED_BITS}
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
				       struct prop_value *pv)
{
	size_t l;

	pv->type = ep->type;
	switch (ep->type) {
	case USER_TA_PROP_TYPE_BOOL:
		l = sizeof(uint32_t);
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
	case USER_TA_PROP_TYPE_BINARY_BLOCK:
		/* Handle too large strings by truncating them */
		strlcpy(pv->u.str_val, ep->value, sizeof(pv->u.str_val));
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_GENERIC;
	}
	memcpy(&pv->u, ep->value, l);
	return TEE_SUCCESS;
}

static TEE_Result propget_get_property(TEE_PropSetHandle h, char *name,
				       struct prop_value *pv)
{
	TEE_Result res;
	const struct user_ta_property *eps;
	size_t eps_len;
	uint32_t prop_type;
	uint32_t index;
	uint32_t size;

	if (h == TEE_PROPSET_CURRENT_TA || h == TEE_PROPSET_CURRENT_CLIENT ||
	    h == TEE_PROPSET_TEE_IMPLEMENTATION) {
		size_t n;

		res = propset_get(h, &eps, &eps_len);
		if (res != TEE_SUCCESS)
			return res;

		for (n = 0; n < eps_len; n++) {
			if (!strcmp(name, eps[n].name))
				return propget_get_ext_prop(eps + n, pv);
		}

		/* get the index from the name */
		res = utee_get_property_name_to_index((unsigned long)h, name,
						strlen(name) + 1, &index);
		if (res != TEE_SUCCESS)
			return res;
		size = sizeof(pv->u);
		res = utee_get_property((unsigned long)h, index, 0, 0,
					&pv->u, &size, &prop_type);
	} else {
		struct prop_enumerator *pe = (struct prop_enumerator *)h;
		uint32_t idx = pe->idx;

		if (idx == PROP_ENUMERATOR_NOT_STARTED)
			return TEE_ERROR_ITEM_NOT_FOUND;

		res = propset_get(pe->prop_set, &eps, &eps_len);
		if (res != TEE_SUCCESS)
			return res;

		if (idx < eps_len)
			return propget_get_ext_prop(eps + idx, pv);
		idx -= eps_len;

		size = sizeof(pv->u);
		res = utee_get_property((unsigned long)pe->prop_set, idx,
					0, 0, &pv->u, &size, &prop_type);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_ERROR_BAD_PARAMETERS;
	}

	if (res == TEE_SUCCESS)
		pv->type = prop_type;
	return res;
}

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
				   char *name, char *valueBuffer,
				   uint32_t *valueBufferLen)
{
	TEE_Result res;
	struct prop_value pv;
	size_t l;
	size_t bufferlen;

	if (valueBuffer == NULL || valueBufferLen == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	bufferlen = *valueBufferLen;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		goto err;

	switch (pv.type) {
	case USER_TA_PROP_TYPE_BOOL:
		l = strlcpy(valueBuffer, pv.u.bool_val ? "true" : "false",
			    bufferlen);
		break;

	case USER_TA_PROP_TYPE_U32:
		l = snprintf(valueBuffer, bufferlen, "%u",
			     (unsigned int)pv.u.int_val);
		break;

	case USER_TA_PROP_TYPE_UUID:
		l = snprintf(valueBuffer, bufferlen,
			     "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
			     (unsigned int)pv.u.uuid_val.timeLow,
			     pv.u.uuid_val.timeMid,
			     pv.u.uuid_val.timeHiAndVersion,
			     pv.u.uuid_val.clockSeqAndNode[0],
			     pv.u.uuid_val.clockSeqAndNode[1],
			     pv.u.uuid_val.clockSeqAndNode[2],
			     pv.u.uuid_val.clockSeqAndNode[3],
			     pv.u.uuid_val.clockSeqAndNode[4],
			     pv.u.uuid_val.clockSeqAndNode[5],
			     pv.u.uuid_val.clockSeqAndNode[6],
			     pv.u.uuid_val.clockSeqAndNode[7]);
		break;

	case USER_TA_PROP_TYPE_IDENTITY:
		l = snprintf(valueBuffer, bufferlen,
			     "%u:%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
			     (unsigned int)pv.u.identity_val.login,
			     (unsigned int)pv.u.identity_val.uuid.timeLow,
			     pv.u.identity_val.uuid.timeMid,
			     pv.u.identity_val.uuid.timeHiAndVersion,
			     pv.u.identity_val.uuid.clockSeqAndNode[0],
			     pv.u.identity_val.uuid.clockSeqAndNode[1],
			     pv.u.identity_val.uuid.clockSeqAndNode[2],
			     pv.u.identity_val.uuid.clockSeqAndNode[3],
			     pv.u.identity_val.uuid.clockSeqAndNode[4],
			     pv.u.identity_val.uuid.clockSeqAndNode[5],
			     pv.u.identity_val.uuid.clockSeqAndNode[6],
			     pv.u.identity_val.uuid.clockSeqAndNode[7]);
		break;

	case USER_TA_PROP_TYPE_STRING:
	case USER_TA_PROP_TYPE_BINARY_BLOCK:
		l = strlcpy(valueBuffer, pv.u.str_val, bufferlen);
		break;

	default:
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	/* The size "must account for the zero terminator" */
	*valueBufferLen = l + 1;

	if (l >= bufferlen) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	goto out;

err:
	if (res == TEE_ERROR_ITEM_NOT_FOUND ||
	    res == TEE_ERROR_SHORT_BUFFER)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
				 char *name, bool *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		goto err;

	if (pv.type != USER_TA_PROP_TYPE_BOOL) {
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	*value = !!pv.u.bool_val;

	goto out;

err:
	if (res == TEE_ERROR_ITEM_NOT_FOUND ||
	    res == TEE_ERROR_BAD_FORMAT)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
				char *name, uint32_t *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		goto err;

	if (pv.type != USER_TA_PROP_TYPE_U32) {
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	*value = pv.u.int_val;

	goto out;

err:
	if (res == TEE_ERROR_ITEM_NOT_FOUND ||
	    res == TEE_ERROR_BAD_FORMAT)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
					char *name, void *valueBuffer,
					uint32_t *valueBufferLen)
{
	TEE_Result res;
	struct prop_value pv;
	void *val;
	int val_len;
	size_t size;

	if (valueBuffer == NULL || valueBufferLen == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		goto err;

	if (pv.type != USER_TA_PROP_TYPE_BINARY_BLOCK) {
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	val = pv.u.str_val;
	val_len = strlen(val);
	size = *valueBufferLen;
	if (!base64_dec(val, val_len, valueBuffer, &size)) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	*valueBufferLen = size;

	goto out;

err:
	if (res == TEE_ERROR_ITEM_NOT_FOUND ||
	    res == TEE_ERROR_BAD_FORMAT ||
	    res == TEE_ERROR_SHORT_BUFFER)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
				 char *name, TEE_UUID *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		goto err;

	if (pv.type != USER_TA_PROP_TYPE_UUID) {
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	*value = pv.u.uuid_val;	/* struct copy */

	goto out;

err:
	if (res == TEE_ERROR_ITEM_NOT_FOUND ||
	    res == TEE_ERROR_BAD_FORMAT)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
				     char *name, TEE_Identity *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		goto err;

	if (pv.type != USER_TA_PROP_TYPE_IDENTITY) {
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	*value = pv.u.identity_val;	/* struct copy */

	goto out;

err:
	if (res == TEE_ERROR_ITEM_NOT_FOUND ||
	    res == TEE_ERROR_BAD_FORMAT)
		return res;
	TEE_Panic(0);
out:
	return TEE_SUCCESS;
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
	TEE_Result res;
	struct prop_enumerator *pe;

	if (enumerator == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

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

	if (pe == NULL)
		return;

	pe->idx = 0;
	pe->prop_set = propSet;
}

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator,
			       void *nameBuffer, uint32_t *nameBufferLen)
{
	TEE_Result res;
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;
	const struct user_ta_property *eps;
	size_t eps_len;
	const char *str;
	size_t bufferlen;

	if (pe == NULL || nameBuffer == NULL || nameBufferLen == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	bufferlen = *nameBufferLen;
	res = propset_get(pe->prop_set, &eps, &eps_len);
	if (res != TEE_SUCCESS)
		goto err;

	if (pe->idx < eps_len) {
		str = eps[pe->idx].name;
		bufferlen = strlcpy(nameBuffer, str, *nameBufferLen);
		if (bufferlen >= *nameBufferLen)
			res = TEE_ERROR_SHORT_BUFFER;
		*nameBufferLen = bufferlen;
	} else {
		res = utee_get_property((unsigned long)pe->prop_set,
					pe->idx - eps_len,
					nameBuffer, nameBufferLen,
					0, 0, 0);
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

	if (pe == NULL) {
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
		res = utee_get_property((unsigned long)pe->prop_set,
					next_idx - eps_len, 0, 0, 0, 0, 0);

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND)
		TEE_Panic(0);
	return res;
}
