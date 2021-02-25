/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PKCS11_ATTRIBUTES_H
#define PKCS11_TA_PKCS11_ATTRIBUTES_H

#include <inttypes.h>

#include "serializer.h"

struct obj_attrs;
struct pkcs11_object;
struct pkcs11_session;

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
 * Utils to check compliance of attributes at various processing steps.
 * Any processing operation is exclusively one of the following.
 *
 * Case 1: Create a secret from some local random value (C_CreateKey & friends)
 * - client provides an attributes list template, PKCS11 TA completes with
 *   default attribute values. Object is created if attributes are
 *   consistent and comply token/session state.
 * - PKCS11 sequence:
 *   - check/set token/session state
 *   - create an attribute list from client template and default values.
 *   - check new secret attributes complies requested mechanism.
 *   - check new secret attributes complies token/session state.
 *   - Generate the value for the secret.
 *   - Set some runtime attributes in the new secret.
 *   - Register the new secret and return a handle for it.
 *
 * Case 2: Create a secret from a client clear data (C_CreateObject)
 * - client provides an attributes list template, PKCS11 TA completes with
 *   default attribute values. Object is created if attributes are
 *   consistent and comply token/session state.
 *   - check/set token/session state
 *   - create an attribute list from client template and default values.
 *   - check new secret attributes complies requested mechanism (raw-import).
 *   - check new secret attributes complies token/session state.
 *   - Set some runtime attributes in the new secret.
 *   - Register the new secret and return a handle for it.

 * Case 3: Use a secret for data processing
 * - client provides a mechanism ID and the secret handle.
 * - PKCS11 checks mechanism and secret comply, if mechanism and token/session
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
 * - PKCS11 create a new-key attribute list based on template + default values +
 *   inheritance from the parent key attributes.
 * - PKCS11 checks:
 *   - token/session state
 *   - parent-key vs mechanism
 *   - parent-key vs token/session state
 *   - parent-key vs new-key
 *   - new-key vs mechanism
 *   - new-key vs token/session state
 * - then do processing
 * - then finalize object creation
 */

enum processing_func {
	PKCS11_FUNCTION_DIGEST,
	PKCS11_FUNCTION_GENERATE,
	PKCS11_FUNCTION_GENERATE_PAIR,
	PKCS11_FUNCTION_DERIVE,
	PKCS11_FUNCTION_WRAP,
	PKCS11_FUNCTION_UNWRAP,
	PKCS11_FUNCTION_ENCRYPT,
	PKCS11_FUNCTION_DECRYPT,
	PKCS11_FUNCTION_SIGN,
	PKCS11_FUNCTION_VERIFY,
	PKCS11_FUNCTION_SIGN_RECOVER,
	PKCS11_FUNCTION_VERIFY_RECOVER,
	PKCS11_FUNCTION_IMPORT,
	PKCS11_FUNCTION_COPY,
	PKCS11_FUNCTION_MODIFY,
	PKCS11_FUNCTION_DESTROY,
	PKCS11_FUNCTION_UNKNOWN,
};

enum processing_step {
	PKCS11_FUNC_STEP_INIT,
	PKCS11_FUNC_STEP_ONESHOT,
	PKCS11_FUNC_STEP_UPDATE,
	PKCS11_FUNC_STEP_UPDATE_KEY,
	PKCS11_FUNC_STEP_FINAL,
};

/* Create an attribute list for a new object */
enum pkcs11_rc
create_attributes_from_template(struct obj_attrs **out, void *template,
				size_t template_size, struct obj_attrs *parent,
				enum processing_func func,
				enum pkcs11_mechanism_id proc_mecha,
				enum pkcs11_class_id template_class);

/*
 * The various checks to be performed before a processing:
 * - create a new object in the current token state
 * - use a parent object in the processing
 * - use a mechanism with provided configuration
 */
enum pkcs11_rc check_created_attrs_against_token(struct pkcs11_session *session,
						 struct obj_attrs *head);

enum pkcs11_rc check_created_attrs_against_processing(uint32_t proc_id,
						      struct obj_attrs *head);

enum pkcs11_rc check_created_attrs(struct obj_attrs *key1,
				   struct obj_attrs *key2);

/*
 * Check the attributes of the parent secret (key) used in the processing
 * do match the target processing.
 *
 * @proc_id - PKCS11_CKM_xxx
 * @func - identifier of the processing function operated with @proc_id.
 * @head - head of the attributes of parent object.
 */
enum pkcs11_rc
check_parent_attrs_against_processing(enum pkcs11_mechanism_id proc_id,
				      enum processing_func func,
				      struct obj_attrs *head);

enum pkcs11_rc check_access_attrs_against_token(struct pkcs11_session *session,
						struct obj_attrs *head);

enum pkcs11_rc
check_mechanism_against_processing(struct pkcs11_session *session,
				   enum pkcs11_mechanism_id mechanism_type,
				   enum processing_func function,
				   enum processing_step step);

bool attribute_is_exportable(struct pkcs11_attribute_head *req_attr,
			     struct pkcs11_object *obj);

bool object_is_private(struct obj_attrs *head);

bool object_is_token(struct obj_attrs *head);

bool object_is_modifiable(struct obj_attrs *head);

bool object_is_copyable(struct obj_attrs *head);

/*
 * Check the attributes passed in template against the attributes which can be
 * modified. These are the attributes marked with * 8,10,11 or 12 in Table 10
 * in PKCS #11 Cryptographic Token InterfaceBase Specification Version 2.40.
 * Few attributes not with this marking but explicitly specified as modifiable
 * in footnote of their tables are also considered to be modifiable
 */
enum pkcs11_rc check_attrs_against_modification(struct pkcs11_session *session,
						struct obj_attrs *head,
						struct pkcs11_object *obj,
						enum processing_func function);

enum pkcs11_rc set_key_data(struct obj_attrs **head, void *data,
			    size_t key_size);

enum pkcs11_rc get_key_data_to_wrap(struct obj_attrs *head, void **data,
				    uint32_t *sz);

/*
 * Adds CKA_ID attribute from paired object if missing.
 *
 * @pub_head - Public key object attributes
 * @priv_head - Private key object attributes
 * Return a PKCS11 return code
 */
enum pkcs11_rc add_missing_attribute_id(struct obj_attrs **pub_head,
					struct obj_attrs **priv_head);

#endif /*PKCS11_TA_PKCS11_ATTRIBUTES_H*/
