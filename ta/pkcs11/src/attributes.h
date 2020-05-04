/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_ATTRIBUTES_H
#define PKCS11_TA_ATTRIBUTES_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

#include "pkcs11_helpers.h"

/*
 * Boolean property attributes (BPA): bit position in a 64 bit mask
 * for boolean properties object can mandate as attribute, depending
 * on the object. These attributes are often accessed and it is
 * quicker to get then from a 64 bit field in the object instance
 * rather than searching into the object attributes.
 */
#define PKCS11_BOOLPROPH_FLAG		BIT32(31)
#define PKCS11_BOOLPROPS_BASE		0
#define PKCS11_BOOLPROPS_MAX_COUNT	64

enum boolprop_attr {
	BPA_TOKEN = 0,
	BPA_PRIVATE,
	BPA_TRUSTED,
	BPA_SENSITIVE,
	BPA_ENCRYPT,
	BPA_DECRYPT,
	BPA_WRAP,
	BPA_UNWRAP,
	BPA_SIGN,
	BPA_SIGN_RECOVER,
	BPA_VERIFY,
	BPA_VERIFY_RECOVER,
	BPA_DERIVE,
	BPA_EXTRACTABLE,
	BPA_LOCAL,
	BPA_NEVER_EXTRACTABLE,
	BPA_ALWAYS_SENSITIVE,
	BPA_MODIFIABLE,
	BPA_COPYABLE,
	BPA_DESTROYABLE,
	BPA_ALWAYS_AUTHENTICATE,
	BPA_WRAP_WITH_TRUSTED,
};

/*
 * Header of a serialised memory object inside PKCS11 TA.
 *
 * @attrs_size; byte size of the serialized data
 * @attrs_count; number of items in the blob
 * @attrs - then starts the blob binary data
 */
struct obj_attrs {
	uint32_t attrs_size;
	uint32_t attrs_count;
	uint8_t attrs[];
};

/*
 * Allocation a reference for a serialized attributes.
 * Can be freed from a simple TEE_Free(reference);
 *
 * Return a PKCS11_OK on success or a PKCS11 return code.
 */
enum pkcs11_rc init_attributes_head(struct obj_attrs **head);

/*
 * Update serialized attributes to add an entry. Can relocate the attribute
 * list buffer.
 *
 * Return a PKCS11_OK on success or a PKCS11 return code.
 */
enum pkcs11_rc add_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size);

/*
 * If *count == 0, count and return in *count the number of attributes matching
 * the input attribute ID.
 *
 * If *count != 0, return the address and size of the attributes found, up to
 * the occurrence number *count. attr and attr_size and expected large
 * enough. attr is the output array of the values found. attr_size is the
 * output array of the size of each values found.
 *
 * If attr_size != NULL, return in in *attr_size attribute value size.
 * If attr != NULL return in *attr the address of the attribute value.
 */
void get_attribute_ptrs(struct obj_attrs *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count);

/*
 * If attributes is not found return PKCS11_NOT_FOUND.
 * If attr_size != NULL, return in *attr_size attribute value size.
 * If attr != NULL, return in *attr the address of the attribute value.
 *
 * Return a PKCS11_OK or PKCS11_NOT_FOUND on success, or a PKCS11 return code.
 */
enum pkcs11_rc get_attribute_ptr(struct obj_attrs *head, uint32_t attribute,
				 void **attr_ptr, uint32_t *attr_size);
/*
 * If attribute is not found, return PKCS11_NOT_FOUND.
 * If attr_size != NULL, check *attr_size matches attributes size of return
 * PKCS11_SHORT_BUFFER with expected size in *attr_size.
 * If attr != NULL and attr_size is NULL or gives expected buffer size,
 * copy attribute value into attr.
 *
 * Return a PKCS11_OK or PKCS11_NOT_FOUND on success, or a PKCS11 return code.
 */
enum pkcs11_rc get_attribute(struct obj_attrs *head, uint32_t attribute,
			     void *attr, uint32_t *attr_size);

static inline enum pkcs11_rc get_u32_attribute(struct obj_attrs *head,
					       uint32_t attribute,
					       uint32_t *attr)
{
	uint32_t size = sizeof(uint32_t);
	enum pkcs11_rc rc = get_attribute(head, attribute, attr, &size);

	if (size != sizeof(uint32_t))
		return PKCS11_CKR_GENERAL_ERROR;

	return rc;
}

/*
 * Some helpers
 */
static inline uint32_t get_class(struct obj_attrs *head)
{
	uint32_t class;
	uint32_t size = sizeof(class);

	if (get_attribute(head, PKCS11_CKA_CLASS, &class, &size))
		return PKCS11_CKO_UNDEFINED_ID;

	return class;
}

static inline uint32_t get_type(struct obj_attrs *head)
{
	uint32_t type;
	uint32_t size = sizeof(type);

	if (get_attribute(head, PKCS11_CKA_KEY_TYPE, &type, &size))
		return PKCS11_CKK_UNDEFINED_ID;

	return type;
}

bool get_bool(struct obj_attrs *head, uint32_t attribute);

#if CFG_TEE_TA_LOG_LEVEL > 0
/* Debug: dump object attributes to IMSG() trace console */
void trace_attributes(const char *prefix, void *ref);
#else
static inline void trace_attributes(const char *prefix __unused,
				    void *ref __unused)
{
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
#endif /*PKCS11_TA_ATTRIBUTES_H*/
