// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <inttypes.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "sanitize_object.h"
#include "serializer.h"

struct pkcs11_object *pkcs11_handle2object(uint32_t handle,
					   struct pkcs11_session *session)
{
	return handle_lookup(&session->object_handle_db, handle);
}

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session)
{
	return handle_lookup_handle(&session->object_handle_db, obj);
}

/* Currently handle pkcs11 sessions and tokens */

static struct object_list *get_session_objects(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_get_session_objects(ck_session);
}

static struct ck_token *get_session_token(void *session)
{
	struct pkcs11_session *ck_session = session;

	return pkcs11_session2token(ck_session);
}

/* Release resources of a non-persistent object */
static void cleanup_volatile_obj_ref(struct pkcs11_object *obj)
{
	if (!obj)
		return;

	if (obj->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj->key_handle);

	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	TEE_Free(obj->attributes);
	TEE_Free(obj->uuid);
	TEE_Free(obj);
}

/* Release resources of a persistent object including volatile resources */
static void cleanup_persistent_object(struct pkcs11_object *obj,
				      struct ck_token *token)
{
	TEE_Result res = TEE_SUCCESS;

	if (!obj)
		return;

	/* Open handle with write properties to destroy the object */
	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       obj->uuid, sizeof(TEE_UUID),
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &obj->attribs_hdl);
	if (!res)
		TEE_CloseAndDeletePersistentObject1(obj->attribs_hdl);

	obj->attribs_hdl = TEE_HANDLE_NULL;
	destroy_object_uuid(token, obj);

	LIST_REMOVE(obj, link);

	cleanup_volatile_obj_ref(obj);
}

/*
 * destroy_object - destroy an PKCS11 TA object
 *
 * @session - session requesting object destruction
 * @obj - reference to the PKCS11 TA object
 * @session_only - true if only session object shall be destroyed
 */
void destroy_object(struct pkcs11_session *session, struct pkcs11_object *obj,
		    bool session_only)
{
#ifdef DEBUG
	trace_attributes("[destroy]", obj->attributes);
	if (obj->uuid)
		MSG_RAW("[destroy] obj uuid %pUl", (void *)obj->uuid);
#endif

	/*
	 * Remove from session list only if it was published.
	 *
	 * This depends on obj->link.le_prev always pointing on the
	 * link.le_next element in the previous object in the list even if
	 * there's only a single object in the list. In the first object in
	 * the list obj->link.le_prev instead points to lh_first in the
	 * list head. If list implementation is changed we need to revisit
	 * this.
	 */
	if (obj->link.le_next || obj->link.le_prev)
		LIST_REMOVE(obj, link);

	if (session_only) {
		/* Destroy object due to session closure */
		handle_put(&session->object_handle_db,
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);

		return;
	}

	/* Destroy target object (persistent or not) */
	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		assert(obj->uuid);
		/* Try twice otherwise panic! */
		if (unregister_persistent_object(session->token, obj->uuid) &&
		    unregister_persistent_object(session->token, obj->uuid))
			TEE_Panic(0);

		handle_put(&session->object_handle_db,
			   pkcs11_object2handle(obj, session));
		cleanup_persistent_object(obj, session->token);
	} else {
		handle_put(&session->object_handle_db,
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);
	}
}

static struct pkcs11_object *create_obj_instance(struct obj_attrs *head)
{
	struct pkcs11_object *obj = NULL;

	obj = TEE_Malloc(sizeof(struct pkcs11_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return NULL;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;

	return obj;
}

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid)
{
	struct pkcs11_object *obj = create_obj_instance(head);

	if (obj)
		obj->uuid = uuid;

	return obj;
}

/*
 * create_object - create an PKCS11 TA object from its attributes and value
 *
 * @sess - session requesting object creation
 * @head - reference to serialized attributes
 * @out_handle - generated handle for the created object
 */
enum pkcs11_rc create_object(void *sess, struct obj_attrs *head,
			     uint32_t *out_handle)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct pkcs11_object *obj = NULL;
	struct pkcs11_session *session = (struct pkcs11_session *)sess;
	uint32_t obj_handle = 0;

#ifdef DEBUG
	trace_attributes("[create]", head);
#endif

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */

	obj = create_obj_instance(head);
	if (!obj)
		return PKCS11_CKR_DEVICE_MEMORY;

	/* Create a handle for the object in the session database */
	obj_handle = handle_get(&session->object_handle_db, obj);
	if (!obj_handle) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto err;
	}

	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		TEE_Result res = TEE_SUCCESS;

		/*
		 * Get an ID for the persistent object
		 * Create the file
		 * Register the object in the persistent database
		 * (move the full sequence to persisent_db.c?)
		 */
		size_t size = sizeof(struct obj_attrs) +
			      obj->attributes->attrs_size;
		uint32_t tee_obj_flags = TEE_DATA_FLAG_ACCESS_READ |
					 TEE_DATA_FLAG_ACCESS_WRITE |
					 TEE_DATA_FLAG_ACCESS_WRITE_META;

		rc = create_object_uuid(get_session_token(session), obj);
		if (rc)
			goto err;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->uuid, sizeof(TEE_UUID),
						 tee_obj_flags,
						 TEE_HANDLE_NULL,
						 obj->attributes, size,
						 &obj->attribs_hdl);
		if (res) {
			rc = tee2pkcs_error(res);
			goto err;
		}

		rc = register_persistent_object(get_session_token(session),
						obj->uuid);
		if (rc)
			goto err;

		LIST_INSERT_HEAD(&session->token->object_list, obj, link);
	} else {
		rc = PKCS11_CKR_OK;
		LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	}

	*out_handle = obj_handle;

	return PKCS11_CKR_OK;
err:
	/* make sure that supplied "head" isn't freed */
	obj->attributes = NULL;
	handle_put(&session->object_handle_db, obj_handle);
	if (get_bool(head, PKCS11_CKA_TOKEN))
		cleanup_persistent_object(obj, session->token);
	else
		cleanup_volatile_obj_ref(obj);

	return rc;
}

enum pkcs11_rc entry_create_object(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct obj_attrs *head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t obj_handle = 0;

	/*
	 * Collect the arguments of the request
	 */

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temporary template once done.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, PKCS11_FUNCTION_IMPORT,
					     PKCS11_PROCESSING_IMPORT,
					     PKCS11_CKO_UNDEFINED_ID);
	TEE_Free(template);
	template = NULL;
	if (rc)
		goto out;

	/*
	 * Check target object attributes match target processing
	 * Check target object attributes match token state
	 */
	rc = check_created_attrs_against_processing(PKCS11_PROCESSING_IMPORT,
						    head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_token(session, head);
	if (rc)
		goto out;

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head, including the key value and are assumed
	 * reliable. Now need to register it and get a handle for it.
	 */
	rc = create_object(session, head, &obj_handle);
	if (rc)
		goto out;

	/*
	 * Now obj_handle (through the related struct pkcs11_object
	 * instance) owns the serialised buffer that holds the object
	 * attributes. We clear reference in head to NULL as the serializer
	 * object is now referred from obj_handle. This allows smooth pass
	 * through free at function exit.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": import object %#"PRIx32,
	     session->handle, obj_handle);

out:
	TEE_Free(template);
	TEE_Free(head);

	return rc;
}

enum pkcs11_rc entry_destroy_object(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	TEE_Param *ctrl = params;
	struct serialargs ctrlargs = { };
	uint32_t object_handle = 0;
	struct pkcs11_session *session = NULL;
	struct pkcs11_object *object = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&ctrlargs, &object_handle);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	object = pkcs11_handle2object(object_handle, session);
	if (!object)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	destroy_object(session, object, false);

	DMSG("PKCS11 session %"PRIu32": destroy object %#"PRIx32,
	     session->handle, object_handle);

	return rc;
}
