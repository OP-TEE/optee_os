/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __PKCS11_ATTRIBUTE_H
#define __PKCS11_ATTRIBUTE_H

#include <inttypes.h>

#include "pkcs11_token.h"
#include "serializer.h"

enum processing_func {
	SKS_FUNCTION_IMPORT,
	SKS_FUNCTION_COPY,
	SKS_FUNCTION_GENERATE,
	SKS_FUNCTION_DERIVE,
	SKS_FUNCTION_WRAP,
	SKS_FUNCTION_UNWRAP,
	SKS_FUNCTION_ENCRYPT,
	SKS_FUNCTION_DECRYPT,
	SKS_FUNCTION_SIGN,
	SKS_FUNCTION_VERIFY,
};

/*
 * PKCS#11 directives on object attributes.
 * Those with a '*' are optional, other must be defined, either by caller
 * or by some known default value.
 *
 * [all] objects:	class
 *
 * [stored] objects:	persistent, need_authen, modifiable, copyable,
 *			destroyable, label*.
 *
 * [data] objects:	[all], [stored], application_id*, object_id*, value.
 *
 * [key] objects:	[all], [stored], type, id*, start_date/end_date*,
 *			derive, local, allowed_mechanisms*.
 *
 * [symm-key]:		[key], sensitive, encrypt, decrypt, sign, verify, wrap,
 *			unwrap, extractable, wrap_with_trusted, trusted,
 *			wrap_template, unwrap_template, derive_template.
 */

/*
 * create_pkcs11_storage_attributes - Setup attribute list for a stored object
 *
 * @obj - output object serialized attribute list
 * @head - head of template provided by client
 *
 * Fill output @obj with the attributes expected for a storage object.
 * Attributes are read from input template (head) or set to the default
 * value defined by the PKCS#11.
 */
uint32_t create_pkcs11_storage_attributes(struct serializer *obj, void *head);

/*
 * create_pkcs11_genkey_attributes - Setup attribute list for a key object
 *
 * @obj - output object serialized attribute list
 * @head - head of template provided by client
 *
 * Fill output @obj with the attributes expected for a generic key object.
 * Attributes are read from input template (head) or set to the default
 * value defined by the PKCS#11.
 *
 * This function relies on create_pkcs11_storage_attributes().
 */
uint32_t create_pkcs11_genkey_attributes(struct serializer *obj, void *head);

/*
 * create_pkcs11_symkey_attributes - Setup attribute list for a symmetric key
 *
 * @obj - output object serialized attribute list
 * @head - head of template provided by client
 *
 * Fill output @obj with the attributes expected for a symmetric key object.
 * Attributes are read from input template (head) or set to the default
 * value defined by the PKCS#11.
 *
 * This function relies on create_pkcs11_genkey_attributes().
 */
uint32_t create_pkcs11_symkey_attributes(struct serializer *obj, void *head);

/*
 * create_pkcs11_data_attributes - Setup the attribute list for a data object
 *
 * @obj - output object serialized attribute list
 * @head - head of template provided by client
 *
 * Fill output @obj with the attributes expected for a raw data object.
 * Attributes are read from input template (head) or set to the default
 * value defined by the PKCS#11.
 *
 * This function relies on create_pkcs11_storage_attributes().
 */
uint32_t create_pkcs11_data_attributes(struct serializer *obj, void *head);

/*
 * Utils to check compliance of attributes at various processing steps.
 * Any rocessing operation is exclusively one of the following.
 *
 * Case 1: Create a secret from some local random value (C_CreateKey & friends)
 * - client provides a attributs list template, pkcs11 complete with default
 *   attribute values. Object is created if attributes are consistent and
 *   comply token/session stte.
 * - SKS sequence:
 *   - check/set token/session state
 *   - create a attribute list from client template and defualt values.
 *   - check new secret attributes complies requested mechanism .
 *   - check new secret attributes complies token/session state.
 *   - Generate the value for the secret.
 *   - Set some runtime attributes in the new secret.
 *   - Register the new secret and return a handle for it.

 *
 * Case 2: Create a secret from a client clear data (C_CreateObject)
 * - client provides a attributs list template, pkcs11 complete with default
 *   attribute values. Object is created if attributes are consitent and
 *   comply token/session state.
 *   - check/set token/session state
 *   - create a attribute list from client template and defualt values.
 *   - check new secret attributes complies requested mechanism (raw-import).
 *   - check new secret attributes complies token/session state.
 *   - Set some runtime attributes in the new secret.
 *   - Register the new secret and return a handle for it.

 * Case 3: Use a secret for data processing
 * - client provides a mechanism ID and the secret handle.
 * - SKS checks mechanism and secret comply, if mechanism and token/session
 *   state comply and last if secret and token/session state comply.
 *   - check/set token/session state
 *   - check secret's parent attributes complies requested processing.
 *   - check secret's parent attributes complies token/session state.
 *   - check new secret attributes complies secret's parent attributes.
 *   - check new secret attributes complies requested mechanism.
 *   - check new secret attributes complies token/session state.
 *
 * Case 4: Create a secret from a client template and a secret's parent
 * (i.e derive a symmetric key)
 * - client args: new-key template, mechanism ID, parent-key handle.
 * - SKS create a new-key attribute list based on template + default values +
 *   inheritance from the parent key attributes.
 * - SKS checks:
 *   - token/session state
 *   - parent-key vs mechanism
 *   - parent-key vs token/session state
 *   - parent-key vs new-key
 *   - new-key vs mechanism
 *   - new-key vs token/session state
 * - then do processing
 * - then finalize object creation
 */

/* Create an attribute list for a new object (TODO: add parent attribs) */
uint32_t create_attributes_from_template(struct sks_sobj_head **out,
					 void *template, size_t template_size,
					 enum processing_func func);

/*
 * The various checks to be performed before a processing:
 * - create an new object in the current token state
 * - use a parent object in the processing
 * - use a mechanism with provided configuration
 */
uint32_t check_created_attrs_against_token(struct pkcs11_session *session,
					   struct sks_sobj_head *head);

uint32_t check_created_attrs_against_parent_key(uint32_t proc_id,
						struct sks_sobj_head *parent,
						struct sks_sobj_head *head);

uint32_t check_created_attrs_against_processing(uint32_t proc_id,
						struct sks_sobj_head *head);

uint32_t check_parent_attrs_against_processing(uint32_t proc_id,
					       enum processing_func func,
					       struct sks_sobj_head *head);

uint32_t check_parent_attrs_against_token(struct pkcs11_session *session,
					  struct sks_sobj_head *head);

#endif /*__PKCS11_ATTRIBUTE_H*/
