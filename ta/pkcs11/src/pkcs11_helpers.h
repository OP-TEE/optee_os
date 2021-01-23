/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_HELPERS_H
#define PKCS11_HELPERS_H

#include <pkcs11_ta.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_internal_api.h>

#include <pkcs11_attributes.h>
#include <token_capabilities.h>

struct pkcs11_object;

/*
 * TEE invocation parameter#0 is an in/out buffer of at least 32bit
 * to store the TA PKCS#11 compliant return value.
 */
#define TEE_PARAM0_SIZE_MIN		sizeof(uint32_t)

/* GPD TEE to PKCS11 status conversion */
enum pkcs11_rc tee2pkcs_error(TEE_Result res);

/*
 * Return true if and only if attribute ID with companion attribute value
 * size do match a valid attribute identifier.
 *
 * @attribute_id - Target PKCS11 attribute ID
 * @size - Byte size of the attribute value, 0 if non-constant size
 */
bool valid_pkcs11_attribute_id(uint32_t attribute_id, uint32_t size);

/*
 * Return type attribute byte size if @attribute_id is the ID of a type
 * attribute or 0 if not.
 */
size_t pkcs11_attr_is_type(uint32_t attribute_id);

/* Return true if the attribute has indirect attributes */
bool pkcs11_attr_has_indirect_attributes(uint32_t attribute_id);

/* Return true if the object class is related to a type-in-class */
bool pkcs11_class_has_type(uint32_t class_id);

/* Return true if the object class relates to a key */
bool pkcs11_attr_class_is_key(uint32_t class_id);

/* Return true if the key type @key_type_id relates to a symmetric key */
bool key_type_is_symm_key(uint32_t key_type_id);

/* Return true if the key type @key_type_id relates to an asymmetric key */
bool key_type_is_asymm_key(uint32_t key_type_id);

/* Boolprop flag shift position if @attribute_id is boolean, else -1 */
int pkcs11_attr2boolprop_shift(uint32_t attribute_id);

/* Convert PKCS11 TA function ID into a TEE crypto operation mode */
void pkcs2tee_mode(uint32_t *tee_id, enum processing_func function);

/* Load TEE operation attributes from a PKCS11 object, return false on error */
bool pkcs2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct pkcs11_object *obj,
			enum pkcs11_attr_id pkcs11_id);

/* Hash and load TEE operation attributes from a PKCS11 object */
enum pkcs11_rc pkcs2tee_load_hashed_attr(TEE_Attribute *tee_ref,
					 uint32_t tee_id,
					 struct pkcs11_object *obj,
					 enum pkcs11_attr_id pkcs11_id,
					 uint32_t tee_algo, void *hash_ptr,
					 uint32_t *hash_size);

/* Return true if attribute is a boolean, false otherwise */
static inline bool pkcs11_attr_is_boolean(enum pkcs11_attr_id id)
{
	return pkcs11_attr2boolprop_shift(id) >= 0;
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/* Id-to-string conversions only for trace support */
const char *id2str_ta_cmd(uint32_t id);
const char *id2str_rc(uint32_t id);
const char *id2str_slot_flag(uint32_t id);
const char *id2str_token_flag(uint32_t id);
const char *id2str_session_flag(uint32_t id);
const char *id2str_session_state(uint32_t id);
const char *id2str_attr(uint32_t id);
const char *id2str_class(uint32_t id);
const char *id2str_type(uint32_t id, uint32_t class);
const char *id2str_key_type(uint32_t id);
const char *id2str_certificate_type(uint32_t id);
const char *id2str_attr_value(uint32_t id, size_t size, void *value);
const char *id2str_proc(uint32_t id);
const char *id2str_function(uint32_t id);

static inline const char *id2str_mechanism(enum pkcs11_mechanism_id id)
{
	return mechanism_string_id(id);
}
#endif /* CFG_TEE_TA_LOG_LEVEL > 0 */
#endif /*PKCS11_HELPERS_H*/
