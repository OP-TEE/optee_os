// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <pkcs11_ta.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "attributes.h"
#include "pkcs11_helpers.h"
#include "serializer.h"

enum pkcs11_rc init_attributes_head(struct obj_attrs **head)
{
	*head = TEE_Malloc(sizeof(**head), TEE_MALLOC_FILL_ZERO);
	if (!*head)
		return PKCS11_CKR_DEVICE_MEMORY;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc add_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size)
{
	size_t buf_len = sizeof(struct obj_attrs) + (*head)->attrs_size;
	char **bstart = (void *)head;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint32_t data32 = 0;

	data32 = attribute;
	rc = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	data32 = size;
	rc = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialize(bstart, &buf_len, data, size);
	if (rc)
		return rc;

	/* Alloced buffer is always well aligned */
	head = (void *)bstart;
	(*head)->attrs_size += 2 * sizeof(uint32_t) + size;
	(*head)->attrs_count++;

	return rc;
}

static enum pkcs11_rc _remove_attribute(struct obj_attrs **head,
					uint32_t attribute, bool empty)
{
	struct obj_attrs *h = *head;
	char *cur = NULL;
	char *end = NULL;
	size_t next_off = 0;

	/* Let's find the target attribute */
	cur = (char *)h + sizeof(struct obj_attrs);
	end = cur + h->attrs_size;
	for (; cur < end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref = { };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		if (empty && pkcs11_ref.size)
			return PKCS11_CKR_FUNCTION_FAILED;

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->attrs_count--;
		h->attrs_size -= next_off;
		end -= next_off;
		next_off = 0;

		return PKCS11_CKR_OK;
	}

	DMSG("Attribute %s (%#x) not found", id2str_attr(attribute), attribute);
	return PKCS11_RV_NOT_FOUND;
}

enum pkcs11_rc remove_empty_attribute(struct obj_attrs **head,
				      uint32_t attribute)
{
	return _remove_attribute(head, attribute, true /* empty */);
}

void get_attribute_ptrs(struct obj_attrs *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count)
{
	char *cur = (char *)head + sizeof(struct obj_attrs);
	char *end = cur + head->attrs_size;
	size_t next_off = 0;
	size_t max_found = *count;
	size_t found = 0;
	void **attr_ptr = attr;
	uint32_t *attr_size_ptr = attr_size;

	for (; cur < end; cur += next_off) {
		/* Structure aligned copy of the pkcs11_ref in the object */
		struct pkcs11_attribute_head pkcs11_ref = { };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		found++;

		if (!max_found)
			continue;	/* only count matching attributes */

		if (attr) {
			if (pkcs11_ref.size)
				*attr_ptr++ = cur + sizeof(pkcs11_ref);
			else
				*attr_ptr++ = NULL;
		}

		if (attr_size)
			*attr_size_ptr++ = pkcs11_ref.size;

		if (found == max_found)
			break;
	}

	/* Sanity */
	if (cur > end) {
		DMSG("Exceeding serial object length");
		TEE_Panic(0);
	}

	*count = found;
}

enum pkcs11_rc get_attribute_ptr(struct obj_attrs *head, uint32_t attribute,
				 void **attr_ptr, uint32_t *attr_size)
{
	size_t count = 1;

	get_attribute_ptrs(head, attribute, attr_ptr, attr_size, &count);

	if (!count)
		return PKCS11_RV_NOT_FOUND;

	if (count != 1)
		return PKCS11_CKR_GENERAL_ERROR;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc get_attribute(struct obj_attrs *head, uint32_t attribute,
			     void *attr, uint32_t *attr_size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	void *attr_ptr = NULL;
	uint32_t size = 0;

	rc = get_attribute_ptr(head, attribute, &attr_ptr, &size);
	if (rc)
		return rc;

	if (attr_size && *attr_size < size) {
		*attr_size = size;
		/* This reuses buffer-to-small for any bad size matching */
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	if (attr)
		TEE_MemMove(attr, attr_ptr, size);

	if (attr_size)
		*attr_size = size;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc set_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = _remove_attribute(head, attribute, false);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		return rc;

	return add_attribute(head, attribute, data, size);
}

enum pkcs11_rc modify_attributes_list(struct obj_attrs **dst,
				      struct obj_attrs *head)
{
	char *cur = (char *)head + sizeof(struct obj_attrs);
	char *end = cur + head->attrs_size;
	size_t len = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	for (; cur < end; cur += len) {
		struct pkcs11_attribute_head *cli_ref = (void *)cur;
		/* Structure aligned copy of the pkcs11_ref in the object */
		struct pkcs11_attribute_head cli_head = { };

		TEE_MemMove(&cli_head, cur, sizeof(cli_head));
		len = sizeof(cli_head) + cli_head.size;

		rc = set_attribute(dst, cli_head.id,
				   cli_head.size ? cli_ref->data : NULL,
				   cli_head.size);
		if (rc)
			return rc;
	}

	return PKCS11_CKR_OK;
}

bool get_bool(struct obj_attrs *head, uint32_t attribute)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t bbool = 0;
	uint32_t size = sizeof(bbool);

	rc = get_attribute(head, attribute, &bbool, &size);

	if (rc == PKCS11_RV_NOT_FOUND)
		return false;

	assert(rc == PKCS11_CKR_OK);
	return bbool;
}

bool attributes_match_reference(struct obj_attrs *candidate,
				struct obj_attrs *ref)
{
	size_t count = ref->attrs_count;
	unsigned char *ref_attr = ref->attrs;
	uint32_t rc = PKCS11_CKR_GENERAL_ERROR;

	if (!ref->attrs_count) {
		DMSG("Empty reference match all");
		return true;
	}

	for (count = 0; count < ref->attrs_count; count++) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		void *value = NULL;
		uint32_t size = 0;

		TEE_MemMove(&pkcs11_ref, ref_attr, sizeof(pkcs11_ref));

		rc = get_attribute_ptr(candidate, pkcs11_ref.id, &value, &size);

		if (rc || !value || size != pkcs11_ref.size ||
		    TEE_MemCompare(ref_attr + sizeof(pkcs11_ref), value, size))
			return false;

		ref_attr += sizeof(pkcs11_ref) + pkcs11_ref.size;
	}

	return true;
}

enum pkcs11_rc attributes_match_add_reference(struct obj_attrs **head,
					      struct obj_attrs *ref)
{
	size_t count = ref->attrs_count;
	unsigned char *ref_attr = ref->attrs;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	if (!ref->attrs_count)
		return PKCS11_CKR_OK;

	for (count = 0; count < ref->attrs_count; count++) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		void *value = NULL;
		uint32_t size = 0;

		TEE_MemMove(&pkcs11_ref, ref_attr, sizeof(pkcs11_ref));

		rc = get_attribute_ptr(*head, pkcs11_ref.id, &value, &size);
		if (rc == PKCS11_RV_NOT_FOUND) {
			rc = add_attribute(head, pkcs11_ref.id,
					   ref_attr + sizeof(pkcs11_ref),
					   pkcs11_ref.size);
			if (rc)
				return rc;
		} else {
			if (rc || !value || size != pkcs11_ref.size ||
			    TEE_MemCompare(ref_attr + sizeof(pkcs11_ref), value,
					   size))
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}

		ref_attr += sizeof(pkcs11_ref) + pkcs11_ref.size;
	}

	return PKCS11_CKR_OK;
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Debug: dump CK attribute array to output trace
 */
#define ATTR_TRACE_FMT	"%s attr %s / %s\t(0x%04"PRIx32" %"PRIu32"-byte"
#define ATTR_FMT_0BYTE	ATTR_TRACE_FMT ")"
#define ATTR_FMT_1BYTE	ATTR_TRACE_FMT ": %02x)"
#define ATTR_FMT_2BYTE	ATTR_TRACE_FMT ": %02x %02x)"
#define ATTR_FMT_3BYTE	ATTR_TRACE_FMT ": %02x %02x %02x)"
#define ATTR_FMT_4BYTE	ATTR_TRACE_FMT ": %02x %02x %02x %02x)"
#define ATTR_FMT_ARRAY	ATTR_TRACE_FMT ": %02x %02x %02x %02x ...)"

static void __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next_off = 0;
	char *prefix2 = NULL;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		uint8_t data[4] = { 0 };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		TEE_MemMove(&data[0], cur + sizeof(pkcs11_ref),
			    MIN(pkcs11_ref.size, sizeof(data)));

		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		switch (pkcs11_ref.size) {
		case 0:
			IMSG_RAW(ATTR_FMT_0BYTE,
				 prefix, id2str_attr(pkcs11_ref.id), "*",
				 pkcs11_ref.id, pkcs11_ref.size);
			break;
		case 1:
			IMSG_RAW(ATTR_FMT_1BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size, data[0]);
			break;
		case 2:
			IMSG_RAW(ATTR_FMT_2BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size, data[0],
				 data[1]);
			break;
		case 3:
			IMSG_RAW(ATTR_FMT_3BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2]);
			break;
		case 4:
			IMSG_RAW(ATTR_FMT_4BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		default:
			IMSG_RAW(ATTR_FMT_ARRAY,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		}

		switch (pkcs11_ref.id) {
		case PKCS11_CKA_WRAP_TEMPLATE:
		case PKCS11_CKA_UNWRAP_TEMPLATE:
		case PKCS11_CKA_DERIVE_TEMPLATE:
			if (pkcs11_ref.size)
				trace_attributes(prefix2,
						 cur + sizeof(pkcs11_ref));
			break;
		default:
			break;
		}
	}

	/* Sanity */
	if (cur != end)
		EMSG("Warning: unexpected alignment in object attributes");

	TEE_Free(prefix2);
}

void trace_attributes(const char *prefix, void *ref)
{
	struct obj_attrs head = { };
	char *pre = NULL;

	TEE_MemMove(&head, ref, sizeof(head));

	if (!head.attrs_count)
		return;

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre) {
		EMSG("%s: out of memory", prefix);
		return;
	}

	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	IMSG_RAW("%s,--- (serial object) Attributes list --------", pre);
	IMSG_RAW("%s| %"PRIu32" item(s) - %"PRIu32" bytes",
		 pre, head.attrs_count, head.attrs_size);

	pre[prefix ? strlen(prefix) : 0] = '|';
	__trace_attributes(pre, (char *)ref + sizeof(head),
			   (char *)ref + sizeof(head) + head.attrs_size);

	IMSG_RAW("%s`-----------------------", prefix ? prefix : "");

	TEE_Free(pre);
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
