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

#include <utee_syscalls.h>

#include "string_ext.h"
#include "base64.h"

#define PROP_STR_MAX    80

#define PROP_ENUMERATOR_NOT_STARTED 0xffffffff

struct prop_enumerator {
	uint32_t idx;
	TEE_PropSetHandle prop_set;
};

struct prop_value {
	enum user_ta_prop_type type;
	union {
		bool bool_val;
		uint32_t int_val;
		TEE_UUID uuid_val;
		TEE_Identity identity_val;
		char str_val[PROP_STR_MAX];
	} u;
};

typedef TEE_Result(*ta_propget_func_t) (struct prop_value *pv);

struct prop_set {
	const char *str;
	ta_propget_func_t get;
};

static TEE_Result propget_gpd_ta_app_id(struct prop_value *pv)
{
	pv->type = USER_TA_PROP_TYPE_UUID;
	return utee_get_property(UTEE_PROP_TA_APP_ID, &pv->u.uuid_val,
				 sizeof(pv->u.uuid_val));
}

static TEE_Result propget_gpd_client_identity(struct prop_value *pv)
{
	pv->type = USER_TA_PROP_TYPE_IDENTITY;
	return utee_get_property(UTEE_PROP_CLIENT_ID, &pv->u.identity_val,
				 sizeof(pv->u.identity_val));
}

static TEE_Result propget_gpd_tee_api_version(struct prop_value *pv)
{
	pv->type = USER_TA_PROP_TYPE_STRING;
	return utee_get_property(UTEE_PROP_TEE_API_VERSION, &pv->u.str_val,
				 sizeof(pv->u.str_val));
}

static TEE_Result propget_gpd_tee_description(struct prop_value *pv)
{
	pv->type = USER_TA_PROP_TYPE_STRING;
	return utee_get_property(UTEE_PROP_TEE_DESCR, &pv->u.str_val,
				 sizeof(pv->u.str_val));
}

static TEE_Result propget_gpd_tee_device_id(struct prop_value *pv)
{
	pv->type = USER_TA_PROP_TYPE_UUID;
	return utee_get_property(UTEE_PROP_TEE_DEV_ID, &pv->u.uuid_val,
				 sizeof(pv->u.uuid_val));
}

static TEE_Result propget_gpd_tee_sys_time_protection_level(struct prop_value
							    *pv)
{
	pv->type = USER_TA_PROP_TYPE_U32;
	return utee_get_property(UTEE_PROP_TEE_SYS_TIME_PROT_LEVEL,
				 &pv->u.int_val, sizeof(pv->u.int_val));
}

static TEE_Result propget_gpd_tee_ta_time_protection_level(struct prop_value
							   *pv)
{
	pv->type = USER_TA_PROP_TYPE_U32;
	return utee_get_property(UTEE_PROP_TEE_TA_TIME_PROT_LEVEL,
				 &pv->u.int_val, sizeof(pv->u.int_val));
}

static TEE_Result propget_gpd_tee_arith_max_big_int_size(struct prop_value *pv)
{
	pv->type = USER_TA_PROP_TYPE_U32;
	pv->u.int_val = TEE_MAX_NUMBER_OF_SUPPORTED_BITS;
	return TEE_SUCCESS;
}

static const struct prop_set propset_current_ta[] = {
	{"gpd.ta.appID", propget_gpd_ta_app_id},
};

static const size_t propset_current_ta_len =
	sizeof(propset_current_ta) / sizeof(propset_current_ta[0]);

static const struct prop_set propset_current_client[] = {
	{"gpd.client.identity", propget_gpd_client_identity},
};

static const size_t propset_current_client_len =
	sizeof(propset_current_client) / sizeof(propset_current_client[0]);

static const struct prop_set propset_implementation[] = {
	{"gpd.tee.apiversion", propget_gpd_tee_api_version},
	{"gpd.tee.description", propget_gpd_tee_description},
	{"gpd.tee.deviceID", propget_gpd_tee_device_id},
	{"gpd.tee.systemTime.protectionLevel",
	 propget_gpd_tee_sys_time_protection_level},
	{"gpd.tee.TAPersistentTime.protectionLevel",
	 propget_gpd_tee_ta_time_protection_level},
	{"gpd.tee.arith.maxBigIntSize", propget_gpd_tee_arith_max_big_int_size},
};

static const size_t propset_implementation_len =
	sizeof(propset_implementation) / sizeof(propset_implementation[0]);

static TEE_Result propset_get(TEE_PropSetHandle h, const struct prop_set **ps,
			      size_t *ps_len,
			      const struct user_ta_property **eps,
			      size_t *eps_len)
{
	if (h == TEE_PROPSET_CURRENT_TA) {
		*ps = propset_current_ta;
		*ps_len = propset_current_ta_len;
		*eps = ta_props;
		*eps_len = ta_num_props;
	} else if (h == TEE_PROPSET_CURRENT_CLIENT) {
		*ps = propset_current_client;
		*ps_len = propset_current_client_len;
		*eps = NULL;
		*eps_len = 0;
	} else if (h == TEE_PROPSET_TEE_IMPLEMENTATION) {
		*ps = propset_implementation;
		*ps_len = propset_implementation_len;
		*eps = NULL;
		*eps_len = 0;
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
	const struct prop_set *ps;
	size_t ps_len;
	const struct user_ta_property *eps;
	size_t eps_len;

	if (h == TEE_PROPSET_CURRENT_TA || h == TEE_PROPSET_CURRENT_CLIENT ||
	    h == TEE_PROPSET_TEE_IMPLEMENTATION) {
		size_t n;

		res = propset_get(h, &ps, &ps_len, &eps, &eps_len);
		if (res != TEE_SUCCESS)
			return res;

		for (n = 0; n < ps_len; n++) {
			if (strcmp(name, ps[n].str) == 0)
				return ps[n].get(pv);
		}
		for (n = 0; n < eps_len; n++) {
			if (strcmp(name, eps[n].name) == 0)
				return propget_get_ext_prop(eps + n, pv);
		}
		return TEE_ERROR_ITEM_NOT_FOUND;
	} else {
		struct prop_enumerator *pe = (struct prop_enumerator *)h;
		uint32_t idx = pe->idx;

		if (idx == PROP_ENUMERATOR_NOT_STARTED)
			return TEE_ERROR_ITEM_NOT_FOUND;

		res = propset_get(pe->prop_set, &ps, &ps_len, &eps, &eps_len);
		if (res != TEE_SUCCESS)
			return res;

		if (idx < ps_len)
			return ps[idx].get(pv);

		idx -= ps_len;
		if (idx < eps_len)
			return propget_get_ext_prop(eps + idx, pv);

		return TEE_ERROR_BAD_PARAMETERS;
	}
}

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
				   char *name, char *valueBuffer,
				   size_t *valueBufferLen)
{
	TEE_Result res;
	struct prop_value pv;
	size_t l;
	size_t bufferlen;

	if (valueBuffer == NULL || valueBufferLen == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	bufferlen = *valueBufferLen;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		return res;

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
		return TEE_ERROR_BAD_FORMAT;
	}

	/* The size "must account for the zero terminator" */
	*valueBufferLen = l + 1;

	if (l >= bufferlen)
		return TEE_ERROR_SHORT_BUFFER;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
				 char *name, bool *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		return res;

	if (pv.type != USER_TA_PROP_TYPE_BOOL)
		return TEE_ERROR_BAD_FORMAT;

	*value = pv.u.bool_val;
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
				char *name, uint32_t *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		return res;

	if (pv.type != USER_TA_PROP_TYPE_U32)
		return TEE_ERROR_BAD_FORMAT;

	*value = pv.u.int_val;
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
					char *name, void *valueBuffer,
					size_t *valueBufferLen)
{
	TEE_Result res;
	struct prop_value pv;
	void *val;
	int val_len;

	if (valueBuffer == NULL || valueBufferLen == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		return res;

	if (pv.type != USER_TA_PROP_TYPE_BINARY_BLOCK)
		return TEE_ERROR_BAD_FORMAT;

	val = pv.u.str_val;
	val_len = strlen(val);
	if (!base64_dec(val, val_len, valueBuffer, valueBufferLen))
		return TEE_ERROR_SHORT_BUFFER;
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
				 char *name, TEE_UUID *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		return res;

	if (pv.type != USER_TA_PROP_TYPE_UUID)
		return TEE_ERROR_BAD_FORMAT;

	*value = pv.u.uuid_val;	/* struct copy */
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
				     char *name, TEE_Identity *value)
{
	TEE_Result res;
	struct prop_value pv;

	if (value == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = propget_get_property(propsetOrEnumerator, name, &pv);
	if (res != TEE_SUCCESS)
		return res;

	if (pv.type != USER_TA_PROP_TYPE_IDENTITY)
		return TEE_ERROR_BAD_FORMAT;

	*value = pv.u.identity_val;	/* struct copy */
	return TEE_SUCCESS;
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
	struct prop_enumerator *pe;

	if (enumerator == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	pe = TEE_Malloc(sizeof(struct prop_enumerator),
			TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (pe == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	*enumerator = (TEE_PropSetHandle) pe;
	TEE_ResetPropertyEnumerator(*enumerator);
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
			       void *nameBuffer, size_t *nameBufferLen)
{
	TEE_Result res;
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;
	const struct prop_set *ps;
	size_t ps_len;
	const struct user_ta_property *eps;
	size_t eps_len;
	size_t l;
	const char *str;
	size_t bufferlen;

	if (pe == NULL || nameBuffer == NULL || nameBufferLen == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	bufferlen = *nameBufferLen;
	res = propset_get(pe->prop_set, &ps, &ps_len, &eps, &eps_len);
	if (res != TEE_SUCCESS)
		return res;

	if (pe->idx < ps_len)
		str = ps[pe->idx].str;
	else if ((pe->idx - ps_len) < eps_len)
		str = ta_props[pe->idx - ps_len].name;
	else
		return TEE_ERROR_ITEM_NOT_FOUND;

	l = strlcpy(nameBuffer, str, bufferlen);

	/* The size "must account for the zero terminator" */
	*nameBufferLen = l + 1;

	if (l >= bufferlen)
		return TEE_ERROR_SHORT_BUFFER;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
	TEE_Result res;
	struct prop_enumerator *pe = (struct prop_enumerator *)enumerator;
	uint32_t next_idx;
	const struct prop_set *ps;
	size_t ps_len;
	const struct user_ta_property *eps;
	size_t eps_len;

	if (pe == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (pe->idx == PROP_ENUMERATOR_NOT_STARTED)
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = propset_get(pe->prop_set, &ps, &ps_len, &eps, &eps_len);
	if (res != TEE_SUCCESS)
		return res;

	next_idx = pe->idx + 1;
	pe->idx = next_idx;
	if (next_idx >= (ps_len + eps_len))
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}
