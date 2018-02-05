/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "sanitize_object.h"
#include "serializer.h"
#include "sks_helpers.h"

/*
 * Functions to generate a serialized object.
 * References are pointers to struct serializer.
 */

#define SKS_ID(sks)			case sks:

static bool consistent_class_and_type(uint32_t object, uint32_t type)
{
	switch (object) {
	case SKS_OBJ_RAW_DATA:
		return true;

	case SKS_OBJ_SYM_KEY:
		switch (type) {
		SKS_KEY_TYPE_IDS
			return true;
		default:
			return false;
		}
	case SKS_OBJ_CK_MECHANISM:
		switch (type) {
		SKS_PROCESSING_IDS
			return true;
		case SKS_PROC_RAW_IMPORT:	/* not exported to client API */
		case SKS_PROC_RAW_COPY:		/* not exported to client API */
		default:
			return false;
		}
	/* TODO: not yet supported... */
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
	case SKS_OBJ_OTP_KEY:
	case SKS_OBJ_CERTIFICATE:
	case SKS_OBJ_CK_DOMAIN_PARAMS:
	case SKS_OBJ_CK_HW_FEATURES:
	default:
		return false;
	}

	return false;
}

/* Sanitize class/type in a client attribute list */
static uint32_t sanitize_class_and_type(struct serializer *dst,
				     void *src)
{
	struct sks_object_head head;
	char *cur;
	char *end;
	size_t len;
	uint32_t class;
	uint32_t type;
	struct sks_reference cli_ref;
	uint32_t __maybe_unused rc;

	TEE_MemMove(&head, src, sizeof(struct sks_object_head));

	/* No attribute read from head */
	dst->class = SKS_UNDEFINED_ID; // head.object;
	dst->type = SKS_UNDEFINED_ID; //head.type;
	cur = (char *)src + sizeof(struct sks_object_head);
	end = cur + head.blobs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of client reference in the object */
		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;


		if (sks_attr_is_class(cli_ref.id)) {

			if (cli_ref.size != sks_attr_is_class(cli_ref.id))
				return SKS_INVALID_ATTRIBUTES;

			TEE_MemMove(&class, cur + sizeof(cli_ref), cli_ref.size);

			if (dst->class != SKS_UNDEFINED_ID &&
			    dst->class != class) {
				EMSG("Conflicting class value");
				return SKS_INVALID_ATTRIBUTES;
			}

			dst->class = class;
			continue;
		}

		/* The attribute is a type-in-class */
		if (sks_attr_is_type(cli_ref.id)) {
			if (cli_ref.size != sks_attr_is_type(cli_ref.id))
				return SKS_INVALID_ATTRIBUTES;

			TEE_MemMove(&type, cur + sizeof(cli_ref), cli_ref.size);

			if (dst->type != SKS_UNDEFINED_ID &&
			    dst->type != type) {
				EMSG("Conflicting type-in-class value");
				return SKS_INVALID_ATTRIBUTES;
			}

			dst->type = type;
		}
	}

	/* Sanity */
	if (cur != end) {
		EMSG("unexpected unalignment\n");
		return SKS_FAILED;
	}

	if (!consistent_class_and_type(dst->class, dst->type)) {
		MSG("inconsistent class/type");
		return SKS_INVALID_ATTRIBUTES;
	}

#ifndef SKS_SHEAD_WITH_TYPE
	rc = serialize_sks_ref(dst, SKS_CLASS, &dst->class, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialize_sks_ref(dst, SKS_TYPE, &dst->type, sizeof(uint32_t));
	if (rc)
		return rc;
#endif

	return SKS_OK;
}

static uint32_t sanitize_boolprop(struct serializer *dst,
				struct sks_reference *cli_ref,
				char *cur,
				uint32_t *sanity)
{
	int shift;
	uint32_t mask;
	uint32_t value;
	uint32_t *boolprop_ptr;
	uint32_t *sanity_ptr;

	/* Get the booloean property shift position and value */
	shift = sks_attr2boolprop_shift(cli_ref->id);
	if (shift < 0)
		return SKS_NOT_FOUND;

	if (shift >= SKS_MAX_BOOLPROP_SHIFT)
		return SKS_FAILED;

	mask = 1 << (shift % 32);
	if ((*(uint8_t *)(cur + sizeof(*cli_ref))) == SKS_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = dst->boolprop + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if (*sanity_ptr & mask && value != (*boolprop_ptr & mask))
		return SKS_INVALID_ATTRIBUTES;

	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

#ifndef SKS_SHEAD_WITH_BOOLPROPS
	/* Store the attribute inside the serialized data */
	if (!(*sanity_ptr & mask)) {
		uint32_t rc;
		uint8_t sks_bool = !!value;

		rc = serialize_sks_ref(dst, SKS_BOOLPROPS_BASE + shift,
					&sks_bool, sizeof(uint8_t));
		if (rc)
			return rc;
	}
#endif

	*sanity_ptr |= mask;

	return SKS_OK;
}

static uint32_t sanitize_boolprops(struct serializer *dst, void *src)
{
	struct sks_object_head head;
	char *cur;
	char *end;
	size_t len;
	struct sks_reference cli_ref;
	uint32_t sanity[SKS_MAX_BOOLPROP_ARRAY] = { 0 };
	uint32_t rc;

	TEE_MemMove(&head, src, sizeof(struct sks_object_head));

	dst->class = SKS_UNDEFINED_ID;
	dst->type = SKS_UNDEFINED_ID;

	cur = (char *)src + sizeof(struct sks_object_head);
	end = cur + head.blobs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of the cli_ref in the object */
		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;

		rc = sanitize_boolprop(dst, &cli_ref, cur, sanity);
		if (rc != SKS_OK && rc != SKS_NOT_FOUND)
			return rc;
	}

	return SKS_OK;
}

/* Counterpart of serialize_indirect_attribute() */
static uint32_t sanitize_indirect_attr(struct serializer *dst, uint32_t object,
				    struct sks_reference *cli_ref, char *cur)
{
	struct serializer obj2;
	uint32_t rc;

	/*
	 * Serialized subblobs: current applicable only the key templates which
	 * are tables of attributes.
	 */
	switch (cli_ref->id) {
	case SKS_WRAP_ATTRIBS:
	case SKS_UNWRAP_ATTRIBS:
	case SKS_DERIVE_ATTRIBS:
		break;
	default:
		return SKS_NOT_FOUND;
	}
	/* Such attributes are expected only for keys (and vendor defined) */
	if (sks_attr_class_is_key(object))
		return SKS_INVALID_ATTRIBUTES;

	/* Build a new serial object while sanitizing the attributes list */
	rc = sanitize_client_object(&obj2, cur + sizeof(*cli_ref),
				    cli_ref->size);
	if (rc)
		return rc;

	rc = serialize_32b(dst, cli_ref->id);
	if (rc)
		return rc;

	rc = serialize_32b(dst, cli_ref->size);
	if (rc)
		return rc;

	rc = serialize_buffer(dst, obj2.buffer, obj2.size);
	if (rc)
		return rc;

	dst->item_count++;

	return rc;
}

uint32_t sanitize_client_object(struct serializer *dst, void *src, size_t size)
{
	struct sks_object_head head;
	uint32_t rc;
	char *cur;
	char *end;
	size_t next;

	if (size < sizeof(struct sks_object_head))
		return SKS_BAD_PARAM;

	TEE_MemMove(&head, src, sizeof(struct sks_object_head));

	if (size < (sizeof(struct sks_object_head) + head.blobs_size))
		return SKS_BAD_PARAM;

	serializer_init(dst);

	rc = sanitize_class_and_type(dst, src);
	if (rc)
		goto bail;

	rc = sanitize_boolprops(dst, src);
	if (rc)
		goto bail;

	cur = (char *)src + sizeof(struct sks_object_head);
	end = cur + head.blobs_size;

	for (; cur < end; cur += next) {
		struct sks_reference cli_ref;

		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		next = sizeof(cli_ref) + cli_ref.size;

		if (sks_attr_is_class(cli_ref.id) ||
		    sks_attr_is_type(cli_ref.id) ||
		    sks_attr2boolprop_shift(cli_ref.id) >= 0)
			continue;

		rc = sanitize_indirect_attr(dst, dst->class, &cli_ref, cur);
		if (rc == SKS_OK)
			continue;
		if (rc != SKS_NOT_FOUND)
			goto bail;

		/* It is a known attribute reference, serialize it */
		if (!valid_sks_attribute_id(cli_ref.id)) {
			EMSG("Invalid attribute id %" PRIx32, cli_ref.id);
			rc = SKS_INVALID_ATTRIBUTES;
			goto bail;
		}

		rc = serialize_buffer(dst, cur, next);
		if (rc)
			goto bail;

		dst->item_count++;
	}

	/* sanity */
	if (cur != end) {
		EMSG("unexpected none alignement\n");
		rc = SKS_FAILED;
		goto bail;
	}

	rc = serializer_sync_head(dst);

bail:
	return rc;
}

/*
 * Debug: dump object attribute array to output trace
 */

static uint32_t trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return SKS_MEMORY;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		// TODO: nice ui to trace the attribute info
		IMSG("%s attr %s (%" PRIx32 " %" PRIx32 " byte) : %02x %02x %02x %02x ...\n",
			prefix, sks2str_attr(sks_ref.id), sks_ref.id, sks_ref.size,
			*((char *)cur + sizeof(sks_ref) + 0),
			*((char *)cur + sizeof(sks_ref) + 1),
			*((char *)cur + sizeof(sks_ref) + 2),
			*((char *)cur + sizeof(sks_ref) + 3));

		switch (sks_ref.id) {
		case SKS_WRAP_ATTRIBS:
		case SKS_UNWRAP_ATTRIBS:
		case SKS_DERIVE_ATTRIBS:
			trace_attributes_from_sobj_head(prefix2,
							cur + sizeof(sks_ref));
			break;
		default:
			break;
		}
	}

	/* sanity */
	if (cur != (char *)end) {
		EMSG("unexpected none alignement\n");
	}

	TEE_Free(prefix2);
	return SKS_OK;
}

uint32_t trace_attributes_from_api_head(const char *prefix, void *ref)
{
	struct sks_object_head head;
	char *pre;
	size_t offset;
	uint32_t rc;

	TEE_MemMove(&head, ref, sizeof(head));


	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre)
		return SKS_MEMORY;
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	// TODO: nice ui to trace the attribute info
	IMSG_RAW("%s,--- (serial object) Attributes list --------\n", pre);
	IMSG_RAW("%s| %" PRIx32 " item(s) - %" PRIu32 " bytes\n",
		pre, head.blobs_count, head.blobs_size);

	offset = sizeof(head);
	pre[prefix ? strlen(prefix) : 0] = '|';
	rc = trace_attributes(pre, (char *)ref + offset,
			      (char *)ref + offset + head.blobs_size);
	if (rc)
		goto bail;

	IMSG_RAW("%s`-----------------------\n", prefix ? prefix : "");

bail:
	TEE_Free(pre);
	return rc;
}
