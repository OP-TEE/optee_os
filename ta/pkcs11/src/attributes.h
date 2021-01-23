/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_ATTRIBUTES_H
#define PKCS11_TA_ATTRIBUTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

#include "pkcs11_helpers.h"

/*
 * Boolean property attributes (BPA): bit position in a 64 bit mask
 * for boolean properties object can mandate as attribute, depending
 * on the object. These attributes are often accessed and it is
 * quicker to get them from a 64 bit field in the object instance
 * rather than searching into the object attributes.
 */
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
 * Header of a serialized memory object inside PKCS11 TA.
 *
 * @attrs_size:	 byte size of the serialized data
 * @attrs_count: number of items in the blob
 * @attrs:	 then starts the blob binary data
 */
struct obj_attrs {
	uint32_t attrs_size;
	uint32_t attrs_count;
	uint8_t attrs[];
};

/*
 * init_attributes_head() - Allocate a reference for serialized attributes
 * @head:	*@head holds the retrieved pointer
 *
 * Retrieved pointer can be freed from a simple TEE_Free(reference).
 *
 * Return PKCS11_CKR_OK on success or a PKCS11 return code.
 */
enum pkcs11_rc init_attributes_head(struct obj_attrs **head);

/*
 * add_attribute() - Update serialized attributes to add an entry.
 *
 * @head:	*@head points to serialized attributes,
 *		can be reallocated as attributes are added
 * @attribute:	Attribute ID to add
 * @data:	Opaque data of attribute
 * @size:	Size of data
 *
 * Return PKCS11_CKR_OK on success or a PKCS11 return code.
 */
enum pkcs11_rc add_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size);

/*
 * Update serialized attributes to remove an empty entry. Can relocate the
 * attribute list buffer. Only 1 instance of the entry is expected.
 *
 * Return PKCS11_CKR_OK on success or a PKCS11 return code.
 */
enum pkcs11_rc remove_empty_attribute(struct obj_attrs **head, uint32_t attrib);

/*
 * get_attribute_ptrs() - Get pointers to attributes with a given ID
 * @head:	Pointer to serialized attributes
 * @attribute:	Attribute ID to look for
 * @attr:	Array of pointers to the data inside @head
 * @attr_size:	Array of uint32_t holding the sizes of each value pointed to
 *		by @attr
 * @count:	Number of elements in the arrays above
 *
 * If *count == 0, count and return in *count the number of attributes matching
 * the input attribute ID.
 *
 * If *count != 0, return the address and size of the attributes found, up to
 * the occurrence number *count. attr and attr_size are expected large
 * enough. attr is the output array of the values found. attr_size is the
 * output array of the size of each value found.
 *
 * If attr_size != NULL, return in *attr_size attribute value size.
 * If attr != NULL return in *attr the address of the attribute value.
 */
void get_attribute_ptrs(struct obj_attrs *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count);

/*
 * get_attribute_ptrs() - Get pointer to the attribute of a given ID
 * @head:	Pointer to serialized attributes
 * @attribute:	Attribute ID
 * @attr:	*@attr holds the retrieved pointer to the attribute value
 * @attr_size:	Size of the attribute value
 *
 * If no matching attributes is found return PKCS11_RV_NOT_FOUND.
 * If attr_size != NULL, return in *attr_size attribute value size.
 * If attr != NULL, return in *attr the address of the attribute value.
 *
 * Return PKCS11_CKR_OK or PKCS11_RV_NOT_FOUND on success, or a PKCS11 return
 * code.
 */
enum pkcs11_rc get_attribute_ptr(struct obj_attrs *head, uint32_t attribute,
				 void **attr_ptr, uint32_t *attr_size);

/*
 * get_attribute() - Copy out the attribute of a given ID
 * @head:	Pointer to serialized attributes
 * @attribute:	Attribute ID to look for
 * @attr:	holds the retrieved attribute value
 * @attr_size:	Size of the attribute value
 *
 * If attribute is not found, return PKCS11_RV_NOT_FOUND.
 *
 * If attr_size != NULL, check that attr has enough room for value (compare
 * against *attr_size), copy attribute value to attr and finally return actual
 * value size in *attr_size.
 *
 * If there is not enough room return PKCS11_CKR_BUFFER_TOO_SMALL with expected
 * size in *attr_size.
 *
 * If attr is NULL and attr_size != NULL return expected buffer size in
 * *attr_size.
 *
 * Return PKCS11_CKR_OK or PKCS11_RV_NOT_FOUND on success, or a PKCS11 return
 * code.
 */
enum pkcs11_rc get_attribute(struct obj_attrs *head, uint32_t attribute,
			     void *attr, uint32_t *attr_size);

/*
 * set_attribute() - Set the attribute of a given ID with value
 * @head:	Pointer to serialized attributes where attribute is to be set,
 *		can be relocated as attributes are modified/added
 * @attribute:	Attribute ID to look for
 * @data:	Holds the attribute value to be set
 * @size:	Size of the attribute value
 *
 * Return PKCS11_CKR_OK on success or a PKCS11 return code.
 */
enum pkcs11_rc set_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size);

/*
 * modify_attributes_list() - Modify the value of attributes in destination
 * attribute list (serialized attributes) based on the value of attributes in
 * the source attribute list
 * @dst:	Pointer to serialized attrbutes where attributes are to be
 *		modified, can be relocated as attributes are modified
 * @head:	Serialized attributes containing attributes which need to be
 *		modified in the destination attribute list
 *
 * Return PKCS11_CKR_OK on success
 */
enum pkcs11_rc modify_attributes_list(struct obj_attrs **dst,
				      struct obj_attrs *head);

/*
 * get_u32_attribute() - Copy out the 32-bit attribute value of a given ID
 * @head:	Pointer to serialized attributes
 * @attribute:	Attribute ID
 * @attr:	holds the retrieved 32-bit attribute value
 *
 * If attribute is not found, return PKCS11_RV_NOT_FOUND.
 * If the retreived attribute doesn't have a 4 byte sized value
 * PKCS11_CKR_GENERAL_ERROR is returned.
 *
 * Return PKCS11_CKR_OK or PKCS11_RV_NOT_FOUND on success, or a PKCS11 return
 * code.
 */

static inline enum pkcs11_rc get_u32_attribute(struct obj_attrs *head,
					       uint32_t attribute,
					       uint32_t *attr)
{
	uint32_t size = sizeof(uint32_t);
	enum pkcs11_rc rc = get_attribute(head, attribute, attr, &size);

	if (!rc && size != sizeof(uint32_t))
		return PKCS11_CKR_GENERAL_ERROR;

	return rc;
}

/*
 * Return true if all attributes from the reference are found and match value
 * in the candidate attribute list.
 */
bool attributes_match_reference(struct obj_attrs *ref,
				struct obj_attrs *candidate);

/*
 * Check attributes from @ref are all found or added in @head
 *
 * Return PKCS11_CKR_OK on success, or a PKCS11 return code.
 */
enum pkcs11_rc attributes_match_add_reference(struct obj_attrs **head,
					      struct obj_attrs *ref);
/*
 * get_class() - Get class ID of an object
 * @head:	Pointer to serialized attributes
 *
 * Returns the class ID of an object on succes or returns
 * PKCS11_CKO_UNDEFINED_ID on error.
 */
static inline enum pkcs11_class_id get_class(struct obj_attrs *head)
{
	uint32_t class = 0;
	uint32_t size = sizeof(class);

	if (get_attribute(head, PKCS11_CKA_CLASS, &class, &size))
		return PKCS11_CKO_UNDEFINED_ID;

	return class;
}

/*
 * get_key_type() - Get the key type of an object
 * @head:	Pointer to serialized attributes
 *
 * Returns the key type of an object on success or returns
 * PKCS11_CKK_UNDEFINED_ID on error.
 */
static inline enum pkcs11_key_type get_key_type(struct obj_attrs *head)
{
	uint32_t type = 0;
	uint32_t size = sizeof(type);

	if (get_attribute(head, PKCS11_CKA_KEY_TYPE, &type, &size))
		return PKCS11_CKK_UNDEFINED_ID;

	return type;
}

/*
 * get_certificate_type() - Get the certificate type of an object
 * @head:	Pointer to serialized attributes
 *
 * Returns the certificate type of an object on success or returns
 * PKCS11_CKC_UNDEFINED_ID on error.
 */
static inline
enum pkcs11_certificate_type get_certificate_type(struct obj_attrs *head)
{
	uint32_t type = 0;

	if (get_u32_attribute(head, PKCS11_CKA_CERTIFICATE_TYPE, &type))
		return PKCS11_CKC_UNDEFINED_ID;

	return type;
}

/*
 * get_mechanism_type() - Get the mechanism type of an object
 * @head:	Pointer to serialized attributes
 *
 * Returns the mechanism type of an object on success or returns
 * PKCS11_CKM_UNDEFINED_ID on error.
 */
static inline enum pkcs11_mechanism_id get_mechanism_type(struct obj_attrs *head)
{
	uint32_t type = 0;
	uint32_t size = sizeof(type);

	if (get_attribute(head, PKCS11_CKA_MECHANISM_TYPE, &type, &size))
		return PKCS11_CKM_UNDEFINED_ID;

	return type;
}

/*
 * get_bool() - Get the bool value of an attribute
 * @head:	Pointer to serialized attributes
 * @attribute:	Attribute ID to look for
 *
 * May assert if attribute ID isn't of the boolean type.
 *
 * Returns the bool value of the supplied attribute ID on success if found
 * else false.
 */
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
