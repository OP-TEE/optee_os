/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <inttypes.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "sks_helpers.h"

static uint32_t set_object_boolprop(struct serializer *obj,
				    uint32_t attribute, uint8_t value)
{
	uint8_t val = value;

	return serializer_add_attribute(obj, attribute, &val, sizeof(uint8_t));
}

static uint8_t *get_object_boolprop_ptr(void *head, uint32_t attribute)
{
	uint32_t rv;
	size_t attr_size;
	void *attr;

	rv = serial_get_attribute_ptr(head, attribute, &attr, &attr_size);

	if (rv || attr_size != sizeof(uint8_t))
		return NULL;

	return attr;
}

static bool get_bool(struct sks_sobj_head *head, uint32_t attr)
{
	uint32_t rc __maybe_unused;
	uint8_t bbool;

	/* Would quicker reading from a bit field */
	rc = serial_get_attribute(head, attr, &bbool, NULL);
	assert(rc == SKS_OK);

	return !!bbool;
}

/* Currently handle pkcs11 sessions and tokens */

static inline bool session_allows_persistent_object(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_session_is_read_write(ck_session);
}

static inline bool session_allows_trusted_object(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_session_is_security_officer(ck_session);
}

/*
 * Object default boolean attributes as per PKCS#11
 */
static uint8_t *pkcs11_object_default_boolprop(uint32_t attribute)
{
	static const uint8_t bool_true = 1;
	static const uint8_t bool_false = 0;

	switch (attribute) {
	/* As per PKCS#11 default value */
	case SKS_MODIFIABLE:
	case SKS_COPYABLE:
	case SKS_DESTROYABLE:
		return (uint8_t *)&bool_true;
	case SKS_PERSISTENT:
	case SKS_NEED_AUTHEN:
	case SKS_SENSITIVE:  /* TODO: symkey false, privkey: token specific */
	/* Token specific default value */
	case SKS_DERIVE:
	case SKS_ENCRYPT:
	case SKS_DECRYPT:
	case SKS_SIGN:
	case SKS_VERIFY:
	case SKS_SIGN_RECOVER:
	case SKS_VERIFY_RECOVER:
	case SKS_WRAP:
	case SKS_UNWRAP:
	case SKS_EXTRACTABLE:
	case SKS_WRAP_FROM_TRUSTED:
	case SKS_TRUSTED:
		return (uint8_t *)&bool_false;
	default:
		DMSG("Unexpected boolprop attribute %" PRIx32, attribute);
		TEE_Panic(0); // FIXME: errno
	}

	/* Keep compiler happy */
	return NULL;
}

/*
 * Object expects several boolean attributes to be set to a default value
 * or to a validate client configuration value. This function append the input
 * attrubute (id/size/value) in the serailzed object.
 */
static uint32_t pkcs11_import_object_boolprop(struct serializer *obj, void *head,
					   uint32_t attribute)
{
	uint8_t *attr = get_object_boolprop_ptr(head, attribute);

	if (!attr)
		attr = pkcs11_object_default_boolprop(attribute);

	/* Boolean attributes are 1byte in the ABI, no alignment issue */
	return serializer_add_attribute(obj, attribute, attr, sizeof(uint8_t));
}

uint32_t create_pkcs11_storage_attributes(struct serializer *obj, void *head)
{
	/* Mandated attributes from template or a know default value */
	uint32_t class;
	const uint32_t boolprops[] = {
		SKS_PERSISTENT, SKS_NEED_AUTHEN, SKS_MODIFIABLE,
		SKS_COPYABLE, SKS_DESTROYABLE,
	};
	/* Optional attributes set if template defines it */
	const uint32_t opt_attrs[] = {
		SKS_LABEL,
	};
	size_t n;
	uint32_t rv;

	serializer_init(obj);

	/* Object class is mandatory */
	class = serial_get_class(head);
	if (class == SKS_UNDEFINED_ID) {
		DMSG("No object class found");
		return SKS_INVALID_ATTRIBUTES;
	}
	rv = serializer_add_attribute(obj, SKS_CLASS, &class, sizeof(uint32_t));
	if (rv)
		return rv;

	/*
	 * Following storage object attributes must be defined,
	 * at least to a default value.
	 */
	for (n = 0; n < ARRAY_SIZE(boolprops); n++) {
		rv = pkcs11_import_object_boolprop(obj, head, boolprops[n]);
		if (rv)
			return rv;
	}

	/* Following attributes may be defined */
	for (n = 0; n < ARRAY_SIZE(opt_attrs); n++) {
		uint32_t size;
		void *value;

		if (serial_get_attribute_ptr(head, opt_attrs[n], &value, &size))
			continue;

		rv = serializer_add_attribute(obj, opt_attrs[n], value, size);
		if (rv)
			return rv;
	}

	return rv;
}

uint32_t create_pkcs11_genkey_attributes(struct serializer *obj, void *head)
{
	/* Mandated attributes from template or a know default value */
	uint32_t type;
	const uint32_t boolprops[] = {
		SKS_DERIVE,
	};
	/* Optional attributes set if template defines it */
	const uint32_t opt_attrs[] = {
		SKS_KEY_ID, SKS_ACTIVATION_DATE, SKS_REVOKATION_DATE,
		SKS_ALLOWED_PROCESSINGS,
	};
	size_t n;
	uint32_t rv;

	rv = create_pkcs11_storage_attributes(obj, head);
	if (rv)
		return rv;

	/* Object type-in-class is mandatory */
	type = serial_get_type(head);
	if (type == SKS_UNDEFINED_ID) {
		DMSG("No object type found");
		return SKS_INVALID_ATTRIBUTES;
	}
	rv = serializer_add_attribute(obj, SKS_TYPE, &type, sizeof(uint32_t));
	if (rv)
		return rv;

	/*
	 * Following generic key attributes must be defined,
	 * at least to a default value.
	 */
	for (n = 0; n < ARRAY_SIZE(boolprops); n++) {
		rv = pkcs11_import_object_boolprop(obj, head, boolprops[n]);
		if (rv)
			return rv;
	}

	/* Following attributes may be defined */
	for (n = 0; n < ARRAY_SIZE(opt_attrs); n++) {
		uint32_t size;
		void *value;

		if (serial_get_attribute_ptr(head, opt_attrs[n], &value, &size))
			continue;

		rv = serializer_add_attribute(obj, opt_attrs[n], value, size);
		if (rv)
			return rv;
	}

	return rv;
}

uint32_t create_pkcs11_symkey_attributes(struct serializer *obj, void *head)
{
	/* Mandated attributes from template or a know default value */
	const uint32_t boolprops[] = {
		SKS_SENSITIVE, SKS_ENCRYPT, SKS_DECRYPT, SKS_SIGN, SKS_VERIFY,
		SKS_WRAP, SKS_UNWRAP, SKS_EXTRACTABLE, SKS_WRAP_FROM_TRUSTED,
		SKS_TRUSTED,
	};
	/* Optional attributes set if template defines it */
	const uint32_t opt_attrs[] = {
		SKS_WRAP_ATTRIBS, SKS_UNWRAP_ATTRIBS, SKS_DERIVE_ATTRIBS,
		SKS_VALUE, SKS_VALUE_LEN,
	};
	size_t n;
	uint32_t rv;
	uint8_t bbool;
	uint32_t class;

	rv = create_pkcs11_genkey_attributes(obj, head);
	if (rv)
		return rv;

	/*
	 * Following symmetric key attributes must be defined,
	 * at least to a default value.
	 */
	for (n = 0; n < ARRAY_SIZE(boolprops); n++) {
		rv = pkcs11_import_object_boolprop(obj, head, boolprops[n]);
		if (rv)
			return rv;
	}

	/* Following attributes may be defined */
	for (n = 0; n < ARRAY_SIZE(opt_attrs); n++) {
		uint32_t size;
		void *value;

		if (serial_get_attribute_ptr(head, opt_attrs[n], &value, &size))
			continue;

		rv = serializer_add_attribute(obj, opt_attrs[n], value, size);
		if (rv)
			return rv;
	}

	/* Set the state attributes according to attributes settigns */
	rv = serializer_sync_head(obj);
	if (rv)
		return rv;

	bbool = *get_object_boolprop_ptr(obj->buffer, SKS_SENSITIVE);
	rv = serializer_add_attribute(obj, SKS_ALWAYS_SENSITIVE,
				      &bbool, sizeof(uint8_t));
	if (rv)
		return rv;

	bbool = !*get_object_boolprop_ptr(obj->buffer, SKS_EXTRACTABLE);
	rv = serializer_add_attribute(obj, SKS_NEVER_EXTRACTABLE,
				      &bbool, sizeof(uint8_t));
	if (rv)
		return rv;

	rv = serializer_sync_head(obj);
	if (rv)
		return rv;

	// TOdo: Sanity to remove
	if (serial_get_attribute((void *)obj->buffer, SKS_CLASS, &class, NULL) ||
	    class != SKS_OBJ_SYM_KEY)
		return SKS_INVALID_ATTRIBUTES;

	return rv;
}

uint32_t create_pkcs11_data_attributes(struct serializer *obj, void *head)
{
	/* Optional attributes set if template defines it */
	const uint32_t opt_attrs[] = {
		SKS_OBJECT_ID, SKS_APPLICATION_ID, SKS_VALUE,
	};
	size_t n;
	uint32_t rv;
	uint32_t class;

	serializer_init(obj);

	rv = create_pkcs11_storage_attributes(obj, head);
	if (rv)
		return rv;

	/* Following attributes may be defined */
	for (n = 0; n < ARRAY_SIZE(opt_attrs); n++) {
		uint32_t size;
		void *value;

		if (serial_get_attribute_ptr(head, opt_attrs[n], &value, &size))
			continue;

		rv = serializer_add_attribute(obj, opt_attrs[n], value, size);
		if (rv)
			return rv;
	}

	rv = serializer_sync_head(obj);
	if (rv)
		return rv;

	// TOdo: Sanity to remove
	if (serial_get_attribute((void *)obj->buffer, SKS_CLASS, &class, NULL) ||
	    class != SKS_OBJ_RAW_DATA)
		return SKS_INVALID_ATTRIBUTES;

	return rv;
}

/* Create an attribute list for a new object */
uint32_t create_attributes_from_template(struct sks_sobj_head **out,
					 void *template, size_t template_size,
					 enum processing_func func)
{
	struct serializer temp;
	struct serializer attrs;
	struct sks_sobj_head *head;
	uint32_t rv;
	uint8_t bbool;

#ifdef DEBUG
	trace_attributes_from_api_head("template", template);
#endif

	rv = sanitize_client_object(&temp, template, template_size);

#ifdef DEBUG
	trace_attributes_from_sobj_head("sanitized", (void *)temp.buffer);
#endif
	if (rv)
		return rv;

	head = (struct sks_sobj_head *)(void *)temp.buffer;

	switch (serial_get_class(head)) {
	case SKS_OBJ_RAW_DATA:
		rv = create_pkcs11_data_attributes(&attrs, head);
		break;
	case SKS_OBJ_SYM_KEY:
		rv = create_pkcs11_symkey_attributes(&attrs, head);
		break;
	default:
		DMSG("Invalid object class 0x%" PRIx32 "/%s",
			serial_get_class(head),
			sks2str_class(serial_get_class(head)));
		rv = SKS_INVALID_ATTRIBUTES;
		break;
	}
	if (rv)
		goto bail;

	/* Set SKS_LOCALLY_GENERATED */
	switch (func) {
	case SKS_FUNCTION_IMPORT:
		bbool = SKS_FALSE;
		break;
	case SKS_FUNCTION_GENERATE:
		bbool = SKS_TRUE;
		break;
	case SKS_FUNCTION_COPY:
		bbool = get_bool(head, SKS_LOCALLY_GENERATED);
		break;
	default:
		TEE_Panic(func);
	}

	rv = set_object_boolprop(&attrs, SKS_LOCALLY_GENERATED, bbool);
	if (rv)
		goto bail;

	rv = serializer_sync_head(&attrs);
	if (rv)
		goto bail;

	*out = (void *)attrs.buffer;
#ifdef DEBUG
	trace_attributes_from_sobj_head("object", (void *)attrs.buffer);
#endif

bail:
	serializer_release_buffer(&temp);
	if (rv)
		serializer_release_buffer(&attrs);

	return rv;
}

static uint32_t check_attrs_misc_integrity(struct sks_sobj_head *head)
{
	/* FIXME: is it useful? */
	if (get_bool(head, SKS_NEVER_EXTRACTABLE) &&
	    get_bool(head, SKS_EXTRACTABLE)) {
		DMSG("Never/Extractable attributes mismatch %d/%d",
			get_bool(head, SKS_NEVER_EXTRACTABLE),
			get_bool(head, SKS_EXTRACTABLE));
		return SKS_INVALID_ATTRIBUTES;
	}

	if (get_bool(head, SKS_ALWAYS_SENSITIVE) &&
	    !get_bool(head, SKS_SENSITIVE)) {
		DMSG("Sensitive/always attributes mismatch %d/%d",
			get_bool(head, SKS_SENSITIVE),
			get_bool(head, SKS_ALWAYS_SENSITIVE));
		return SKS_INVALID_ATTRIBUTES;
	}

	return SKS_OK;
}

/*
 * Check the attributes of a to-be-created object matches the token state
 */
uint32_t check_created_attrs_against_token(struct pkcs11_session *session,
					   struct sks_sobj_head *head)
{
	uint32_t rc;

	rc = check_attrs_misc_integrity(head);
	if (rc)
		return rc;

	if (get_bool(head, SKS_TRUSTED) &&
	    !session_allows_trusted_object(session)) {
		DMSG("Can't create trusted object");
		return SKS_CK_NOT_PERMITTED;		// TODO: errno
	}

	if (get_bool(head, SKS_PERSISTENT) &&
	    !session_allows_persistent_object(session)) {
		DMSG("Can't create persistent object");
		return SKS_CK_SESSION_IS_READ_ONLY;
	}

	/*
	 * TODO: ACTIVATION_DATE and REVOKATION_DATE: complies with current
	 * time?
	 */
	return SKS_OK;
}

/*
 * Check the attributes of new secret match the requirements of the parent key.
 */
uint32_t check_created_attrs_against_parent_key(
					uint32_t proc_id __unused,
					struct sks_sobj_head *parent __unused,
					struct sks_sobj_head *head __unused)
{
	/*
	 * TODO
	 * Depends on the processing§/mechanism used.
	 * Wrapping: check head vs parent key WRAP_TEMPLATE attribute.
	 * Unwrapping: check head vs parent key UNWRAP_TEMPLATE attribute.
	 * Derive: check head vs parent key DERIVE_TEMPLATE attribute (late comer?).
	 */
	return SKS_OK;
}

#define DMSG_BAD_BBOOL(attr, proc, head) \
	do {	\
		uint8_t bvalue __maybe_unused;			\
								\
		DMSG("%s issue for %s: %sfound, value %d",	\
			sks2str_attr(attr),			\
			sks2str_proc(proc),			\
			serial_get_attribute(head, attr, &bvalue, NULL) ? \
			"not " : "",				\
			bvalue);				\
	} while (0)

/*
 * Check the attributes of a new secret match the processing/mechanism
 * used to create it.
 *
 * @proc_id - SKS_PROC_xxx
 * @subproc_id - boolean attribute id as encrypt/decrypt/sign/verify,
 *		 if applicable to proc_id.
 * @head - head of the attributes of the to-be-created object.
 */
uint32_t check_created_attrs_against_processing(uint32_t proc_id,
						struct sks_sobj_head *head)
{
	uint8_t bbool;

	/*
	 * Processings that do not create secrets are not expected to call
	 * this function which would return SKS_INVALID_PROC.
	 */
	switch (proc_id) {
	case SKS_PROC_RAW_IMPORT:
		/* sanity: these can be asserted */
		if (serial_get_attribute(head, SKS_LOCALLY_GENERATED,
					 &bbool, NULL) || bbool) {
			DMSG_BAD_BBOOL(SKS_LOCALLY_GENERATED, proc_id, head);
			return SKS_INVALID_ATTRIBUTES;
		}

		return SKS_OK;

	default:
		DMSG("Processing %s not supported", sks2str_proc(proc_id));
		return SKS_INVALID_PROC;
	}
}

/* Check processing ID against attributre ALLOWED_PROCESSINGS if any */
static bool parent_key_complies_allowed_processings(uint32_t proc_id,
						    struct sks_sobj_head *head)
{
	char *attr;
	size_t size;
	uint32_t proc;
	size_t count;

	/*
	 * If key does not specify the allowed processing, assume it is
	 * allowed.
	 */
	if (serial_get_attribute_ptr(head, SKS_ALLOWED_PROCESSINGS,
				     (void **)&attr, &size))
			return true;

	for (count = size / sizeof(uint32_t); count; count--) {
		TEE_MemMove(&proc, attr, sizeof(uint32_t));
		attr += sizeof(uint32_t);

		if (proc == proc_id)
			return true;
	}

	DMSG("can't find %s in allowed list", sks2str_proc(proc_id));
	return false;
}

/*
 * Check the attributes of the parent secret (key) used in the processing
 * do match the target processing.
 *
 * @proc_id - SKS_PROC_xxx
 * @subproc_id - boolean attribute encrypt or decrypt or sign or verify, if
 *		 applicable to proc_id.
 * @head - head of the attributes of parent object.
 */
uint32_t check_parent_attrs_against_processing(uint32_t proc_id,
					       enum processing_func func,
					       struct sks_sobj_head *head)
{
	uint32_t rc __maybe_unused;
	uint8_t bbool;
	size_t size = sizeof(uint8_t);
	uint32_t key_class = serial_get_class(head);
	uint32_t key_type = serial_get_type(head);

	/* Check encrypt/decrypt/sign/verify against target processing */
	if (func == SKS_FUNCTION_ENCRYPT) {
		rc = serial_get_attribute(head, SKS_ENCRYPT, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("encrypt not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}
	if (func == SKS_FUNCTION_DECRYPT) {
		rc = serial_get_attribute(head, SKS_DECRYPT, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("decrypt not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}
	if (func == SKS_FUNCTION_SIGN) {
		rc = serial_get_attribute(head, SKS_SIGN, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("sign not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}
	if (func == SKS_FUNCTION_VERIFY) {
		rc = serial_get_attribute(head, SKS_VERIFY, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("verify not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}
	if (func == SKS_FUNCTION_WRAP) {
		rc = serial_get_attribute(head, SKS_WRAP, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("wrap not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}
	if (func == SKS_FUNCTION_UNWRAP) {
		rc = serial_get_attribute(head, SKS_UNWRAP, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("unwrap not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}
	if (func == SKS_FUNCTION_DERIVE) {
		rc = serial_get_attribute(head, SKS_DERIVE, &bbool, &size);
		assert(rc == SKS_OK);
		if (!bbool) {
			DMSG("derive not permitted");
			return SKS_CK_NOT_PERMITTED;
		}
	}

	/* Check processing complies for parent key family */
	switch (proc_id) {
	case SKS_PROC_AES_ECB_NOPAD:
	case SKS_PROC_AES_CBC_NOPAD:
	case SKS_PROC_AES_CBC_PAD:
	case SKS_PROC_AES_CTS:
	case SKS_PROC_AES_CTR:
	case SKS_PROC_AES_GCM:
	case SKS_PROC_AES_CCM:
		if (key_class == SKS_OBJ_SYM_KEY && key_type == SKS_KEY_AES)
			break;

		DMSG("%s expect an aes key only", sks2str_proc(proc_id));
		return SKS_CK_NOT_PERMITTED;

	default:
		DMSG("Processing not supported 0x%" PRIx32 " (%s)", proc_id,
			sks2str_proc(proc_id));
		return SKS_INVALID_PROC;
	}

	if (!parent_key_complies_allowed_processings(proc_id, head))
		return SKS_CK_NOT_PERMITTED;

	return SKS_OK;
}

/*
 * Check the attributes of a new secret match the token/session state
 *
 * @session - session reference
 * @head - head of the attributes of the to-be-created object
 * Return SKS_OK on compliance or an error code.
 */
uint32_t check_parent_attrs_against_token(struct pkcs11_session *session __unused,
					  struct sks_sobj_head *head)
{
	if (get_bool(head, SKS_NEED_AUTHEN)) {
		/* TODO: add some user authentication means */
		return SKS_CK_NOT_PERMITTED;	// FIXME: SKS_NOT_AUTHENTIFIED
	}

	/*
	 * TODO: ACTIVATION_DATE and REVOKATION_DATE
	 */

	return SKS_OK;
}

