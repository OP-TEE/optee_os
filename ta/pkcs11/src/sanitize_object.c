// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "attributes.h"
#include "pkcs11_helpers.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "token_capabilities.h"

/*
 * Functions to generate a serialized object.
 * References are pointers to struct serializer.
 */
#define PKCS11_ID(id)			case id:

bool sanitize_consistent_class_and_type(struct obj_attrs *attrs)
{
	switch (get_class(attrs)) {
	case PKCS11_CKO_DATA:
		return true;
	case PKCS11_CKO_SECRET_KEY:
		return key_type_is_symm_key(get_type(attrs));
	case PKCS11_CKO_MECHANISM:
		return mechanism_is_valid(get_type(attrs));
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		return key_type_is_asymm_key(get_type(attrs));
	case PKCS11_CKO_OTP_KEY:
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_DOMAIN_PARAMETERS:
	case PKCS11_CKO_HW_FEATURE:
	default:
		return false;
	}

	return false;
}

/* Sanitize class/type in a client attribute list */
static enum pkcs11_rc sanitize_class_and_type(struct obj_attrs **dst, void *src)
{
	struct pkcs11_object_head head = { };
	char *cur = NULL;
	char *end = NULL;
	size_t len = 0;
	uint32_t class_found = 0;
	uint32_t type_found = 0;
	struct pkcs11_attribute_head cli_ref = { };
	uint32_t rc = PKCS11_CKR_OK;
	size_t src_size = 0;

	TEE_MemMove(&head, src, sizeof(head));
	TEE_MemFill(&cli_ref, 0, sizeof(cli_ref));

	src_size = sizeof(struct pkcs11_object_head) + head.attrs_size;

	class_found = PKCS11_CKO_UNDEFINED_ID;
	type_found = PKCS11_CKK_UNDEFINED_ID;

	cur = (char *)src + sizeof(struct pkcs11_object_head);
	end = cur + head.attrs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of client reference in the object */
		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;

		if (cli_ref.id == PKCS11_CKA_CLASS) {
			uint32_t class;

			if (cli_ref.size != sizeof(class)) {
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			TEE_MemMove(&class, cur + sizeof(cli_ref),
				    cli_ref.size);

			if (class_found != PKCS11_CKO_UNDEFINED_ID &&
			    class_found != class) {
				EMSG("Conflicting class value");
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			class_found = class;
			continue;
		}

		/* The attribute is a type-in-class */
		if (pkcs11_attr_is_type(cli_ref.id)) {
			uint32_t type = 0;

			if (cli_ref.size != pkcs11_attr_is_type(cli_ref.id)) {
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			TEE_MemMove(&type, cur + sizeof(cli_ref), cli_ref.size);

			if (type_found != PKCS11_CKK_UNDEFINED_ID &&
			    type_found != type) {
				EMSG("Conflicting type-in-class value");
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			type_found = type;
		}
	}

	/* Sanity */
	if (cur != end) {
		EMSG("Unexpected alignment issue");
		rc = PKCS11_CKR_FUNCTION_FAILED;
		goto err;
	}

	if (class_found != PKCS11_CKO_UNDEFINED_ID) {
		rc = add_attribute(dst, PKCS11_CKA_CLASS,
				   &class_found, sizeof(uint32_t));
		if (rc)
			goto err;
	}

	if (type_found != PKCS11_CKK_UNDEFINED_ID) {
		rc = add_attribute(dst, PKCS11_CKA_KEY_TYPE,
				   &type_found, sizeof(uint32_t));
	}

	return PKCS11_CKR_OK;

err:
	trace_attributes_from_api_head("bad-template", src, src_size);

	return rc;
}

static enum pkcs11_rc sanitize_boolprop(struct obj_attrs **dst,
					struct pkcs11_attribute_head *cli_ref,
					char *cur, uint32_t *boolprop_base,
					uint32_t *sanity)
{
	int shift = 0;
	uint32_t mask = 0;
	uint32_t value = 0;
	uint32_t *boolprop_ptr = NULL;
	uint32_t *sanity_ptr = NULL;

	/* Get the boolean property shift position and value */
	shift = pkcs11_attr2boolprop_shift(cli_ref->id);
	if (shift < 0)
		return PKCS11_RV_NOT_FOUND;

	if (shift >= PKCS11_BOOLPROPS_MAX_COUNT)
		return PKCS11_CKR_FUNCTION_FAILED;

	mask = 1 << (shift % 32);
	if ((*(uint8_t *)(cur + sizeof(*cli_ref))) == PKCS11_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = boolprop_base + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if (*sanity_ptr & mask && value != (*boolprop_ptr & mask))
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;

	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

	/* Store the attribute inside the serialized data */
	if (!(*sanity_ptr & mask)) {
		enum pkcs11_rc rc = PKCS11_CKR_OK;
		uint8_t pkcs11_bool = !!value;

		rc = add_attribute(dst, cli_ref->id, &pkcs11_bool,
				   sizeof(uint8_t));
		if (rc)
			return rc;
	}

	*sanity_ptr |= mask;

	return PKCS11_CKR_OK;
}

static enum pkcs11_rc sanitize_boolprops(struct obj_attrs **dst, void *src)
{
	struct pkcs11_object_head head = { };
	char *cur = NULL;
	char *end = NULL;
	size_t len = 0;
	struct pkcs11_attribute_head cli_ref = { };
	uint32_t sanity[PKCS11_BOOLPROPS_MAX_COUNT] = { 0 };
	uint32_t boolprops[PKCS11_BOOLPROPS_MAX_COUNT] = { 0 };
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	TEE_MemMove(&head, src, sizeof(head));
	TEE_MemFill(&cli_ref, 0, sizeof(cli_ref));

	cur = (char *)src + sizeof(struct pkcs11_object_head);
	end = cur + head.attrs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of the cli_ref in the object */
		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;

		rc = sanitize_boolprop(dst, &cli_ref, cur, boolprops, sanity);
		if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
			return rc;
	}

	return PKCS11_CKR_OK;
}

/* Counterpart of serialize_indirect_attribute() */
static uint32_t sanitize_indirect_attr(struct obj_attrs **dst,
				       struct pkcs11_attribute_head *cli_ref,
				       char *cur)
{
	struct obj_attrs *obj2 = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	enum pkcs11_class_id class = get_class(*dst);

	if (class == PKCS11_CKO_UNDEFINED_ID)
		return PKCS11_CKR_GENERAL_ERROR;

	/*
	 * Serialized attributes: current applicable only the key templates
	 * which are tables of attributes.
	 */
	switch (cli_ref->id) {
	case PKCS11_CKA_WRAP_TEMPLATE:
	case PKCS11_CKA_UNWRAP_TEMPLATE:
	case PKCS11_CKA_DERIVE_TEMPLATE:
		break;
	default:
		return PKCS11_RV_NOT_FOUND;
	}
	/* Such attributes are expected only for keys (and vendor defined) */
	if (pkcs11_attr_class_is_key(class))
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;

	rc = init_attributes_head(&obj2);
	if (rc)
		return rc;

	/* Build a new serial object while sanitizing the attributes list */
	rc = sanitize_client_object(&obj2, cur + sizeof(*cli_ref),
				    cli_ref->size);
	if (rc)
		return rc;

	return add_attribute(dst, cli_ref->id, obj2,
			     sizeof(struct obj_attrs) + obj2->attrs_size);
}

enum pkcs11_rc sanitize_client_object(struct obj_attrs **dst, void *src,
				      size_t size)
{
	struct pkcs11_object_head head = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	char *cur = NULL;
	char *end = NULL;
	size_t next = 0;

	TEE_MemFill(&head, 0, sizeof(head));

	if (size < sizeof(struct pkcs11_object_head))
		return PKCS11_CKR_ARGUMENTS_BAD;

	TEE_MemMove(&head, src, sizeof(struct pkcs11_object_head));

	if (size < (sizeof(struct pkcs11_object_head) + head.attrs_size))
		return PKCS11_CKR_ARGUMENTS_BAD;

	rc = init_attributes_head(dst);
	if (rc)
		return rc;

	rc = sanitize_class_and_type(dst, src);
	if (rc)
		goto bail;

	rc = sanitize_boolprops(dst, src);
	if (rc)
		goto bail;

	cur = (char *)src + sizeof(struct pkcs11_object_head);
	end = cur + head.attrs_size;

	for (; cur < end; cur += next) {
		struct pkcs11_attribute_head cli_ref;

		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		next = sizeof(cli_ref) + cli_ref.size;

		if (cli_ref.id == PKCS11_CKA_CLASS ||
		    pkcs11_attr_is_type(cli_ref.id) ||
		    pkcs11_attr_is_boolean(cli_ref.id))
			continue;

		rc = sanitize_indirect_attr(dst, &cli_ref, cur);
		if (rc == PKCS11_CKR_OK)
			continue;
		if (rc != PKCS11_RV_NOT_FOUND)
			goto bail;

		if (!valid_pkcs11_attribute_id(cli_ref.id, cli_ref.size)) {
			EMSG("Invalid attribute id %#"PRIx32, cli_ref.id);
			rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
			goto bail;
		}

		rc = add_attribute(dst, cli_ref.id, cur + sizeof(cli_ref),
				   cli_ref.size);
		if (rc)
			goto bail;
	}

	/* sanity */
	if (cur != end) {
		EMSG("Unexpected alignment issue");
		rc = PKCS11_CKR_FUNCTION_FAILED;
		goto bail;
	}

bail:
	return rc;
}

/*
 * Debug: dump object attribute array to output trace
 */

static void __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
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

	for (; cur < (char *)end; cur += next) {
		struct pkcs11_attribute_head pkcs11_ref;
		uint8_t data[4] = { 0 };
		uint32_t data_u32 = 0;

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		TEE_MemMove(&data[0], cur + sizeof(pkcs11_ref),
			    MIN(pkcs11_ref.size, sizeof(data)));
		TEE_MemMove(&data_u32, cur + sizeof(pkcs11_ref),
			    sizeof(data_u32));

		next = sizeof(pkcs11_ref) + pkcs11_ref.size;

		IMSG_RAW("%s Attr %s / %s (%#04"PRIx32" %"PRIu32"-byte)",
			 prefix, id2str_attr(pkcs11_ref.id),
			 id2str_attr_value(pkcs11_ref.id, pkcs11_ref.size,
					   cur + sizeof(pkcs11_ref)),
			 pkcs11_ref.id, pkcs11_ref.size);

		switch (pkcs11_ref.size) {
		case 0:
			break;
		case 1:
			DMSG_RAW("%s Attr byte value: %02x", prefix, data[0]);
			break;
		case 2:
			DMSG_RAW("%s Attr byte value: %02x %02x",
				 prefix, data[0], data[1]);
			break;
		case 3:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x",
				 prefix, data[0], data[1], data[2]);
			break;
		case 4:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x %02x",
				 prefix, data[0], data[1], data[2], data[3]);
			break;
		default:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x %02x ...",
				 prefix, data[0], data[1], data[2], data[3]);
			break;
		}

		switch (pkcs11_ref.id) {
		case PKCS11_CKA_WRAP_TEMPLATE:
		case PKCS11_CKA_UNWRAP_TEMPLATE:
		case PKCS11_CKA_DERIVE_TEMPLATE:
			trace_attributes_from_api_head(prefix2,
						       cur + sizeof(pkcs11_ref),
						       (char *)end - cur);
			break;
		default:
			break;
		}
	}

	/* Sanity */
	if (cur != (char *)end)
		EMSG("Warning: unexpected alignment issue");

	TEE_Free(prefix2);
}

void trace_attributes_from_api_head(const char *prefix, void *ref, size_t size)
{
	struct pkcs11_object_head head = { };
	char *pre = NULL;
	size_t offset = 0;

	TEE_MemMove(&head, ref, sizeof(head));

	if (size > sizeof(head) + head.attrs_size) {
		EMSG("template overflows client buffer (%zu/%zu)",
		     size, sizeof(head) + head.attrs_size);
		return;
	}

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

	offset = sizeof(head);
	pre[prefix ? strlen(prefix) : 0] = '|';
	__trace_attributes(pre, (char *)ref + offset,
			   (char *)ref + offset + head.attrs_size);

	IMSG_RAW("%s`-----------------------", prefix ? prefix : "");

	TEE_Free(pre);
}
