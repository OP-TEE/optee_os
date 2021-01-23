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

/*
 * Temporary list used to register allocated struct pkcs11_object instances
 * so that destroy_object() can unconditionally remove the object from its
 * list, being from an object destruction request or because object creation
 * failed before being completed. Objects are moved to their target list at
 * creation completion.
 */
LIST_HEAD(temp_obj_list, pkcs11_object) temporary_object_list =
	LIST_HEAD_INITIALIZER(temp_obj_list);

static struct ck_token *get_session_token(void *session);

struct pkcs11_object *pkcs11_handle2object(uint32_t handle,
					   struct pkcs11_session *session)
{
	struct pkcs11_object *object = NULL;

	object = handle_lookup(get_object_handle_db(session), handle);
	if (!object)
		return NULL;

	/*
	 * If object is session only then no extra checks are needed as session
	 * objects has flat access control space
	 */
	if (!object->token)
		return object;

	/*
	 * Only allow access to token object if session is associated with
	 * the token
	 */
	if (object->token != get_session_token(session))
		return NULL;

	return object;
}

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session)
{
	return handle_lookup_handle(get_object_handle_db(session), obj);
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
void cleanup_persistent_object(struct pkcs11_object *obj,
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

	LIST_REMOVE(obj, link);

	if (session_only) {
		/* Destroy object due to session closure */
		handle_put(get_object_handle_db(session),
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

		handle_put(get_object_handle_db(session),
			   pkcs11_object2handle(obj, session));
		cleanup_persistent_object(obj, session->token);
	} else {
		handle_put(get_object_handle_db(session),
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);
	}
}

static struct pkcs11_object *create_obj_instance(struct obj_attrs *head,
						 struct ck_token *token)
{
	struct pkcs11_object *obj = NULL;

	obj = TEE_Malloc(sizeof(struct pkcs11_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return NULL;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;
	obj->token = token;

	return obj;
}

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid,
					  struct ck_token *token)
{
	struct pkcs11_object *obj = create_obj_instance(head, token);

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

	obj = create_obj_instance(head, NULL);
	if (!obj)
		return PKCS11_CKR_DEVICE_MEMORY;

	LIST_INSERT_HEAD(&temporary_object_list, obj, link);

	/* Create a handle for the object in the session database */
	obj_handle = handle_get(get_object_handle_db(session), obj);
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

		TEE_CloseObject(obj->attribs_hdl);
		obj->attribs_hdl = TEE_HANDLE_NULL;

		/* Move object from temporary list to target token list */
		LIST_REMOVE(obj, link);
		LIST_INSERT_HEAD(&session->token->object_list, obj, link);
	} else {
		/* Move object from temporary list to target session list */
		LIST_REMOVE(obj, link);
		LIST_INSERT_HEAD(get_session_objects(session), obj, link);
		rc = PKCS11_CKR_OK;
	}

	*out_handle = obj_handle;

	return PKCS11_CKR_OK;
err:
	/* make sure that supplied "head" isn't freed */
	obj->attributes = NULL;
	handle_put(get_object_handle_db(session), obj_handle);
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

	rc = check_access_attrs_against_token(session, head);
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
	 * instance) owns the serialized buffer that holds the object
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

	/* Only session objects can be destroyed during a read-only session */
	if (get_bool(object->attributes, PKCS11_CKA_TOKEN) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't destroy persistent object");
		return PKCS11_CKR_SESSION_READ_ONLY;
	}

	/*
	 * Only public objects can be destroyed unless normal user is logged in
	 */
	rc = check_access_attrs_against_token(session, object->attributes);
	if (rc)
		return PKCS11_CKR_USER_NOT_LOGGED_IN;

	/* Objects with PKCS11_CKA_DESTROYABLE as false aren't destroyable */
	if (!get_bool(object->attributes, PKCS11_CKA_DESTROYABLE))
		return PKCS11_CKR_ACTION_PROHIBITED;

	destroy_object(session, object, false);

	DMSG("PKCS11 session %"PRIu32": destroy object %#"PRIx32,
	     session->handle, object_handle);

	return rc;
}

static void release_find_obj_context(struct pkcs11_find_objects *find_ctx)
{
	if (!find_ctx)
		return;

	TEE_Free(find_ctx->attributes);
	TEE_Free(find_ctx->handles);
	TEE_Free(find_ctx);
}

static enum pkcs11_rc find_ctx_add(struct pkcs11_find_objects *find_ctx,
				   uint32_t handle)
{
	uint32_t *hdls = TEE_Realloc(find_ctx->handles,
				     (find_ctx->count + 1) * sizeof(*hdls));

	if (!hdls)
		return PKCS11_CKR_DEVICE_MEMORY;

	find_ctx->handles = hdls;

	*(find_ctx->handles + find_ctx->count) = handle;
	find_ctx->count++;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_find_objects_init(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *sess = NULL;
	struct pkcs11_object_head *template = NULL;
	struct obj_attrs *req_attrs = NULL;
	struct pkcs11_object *obj = NULL;
	struct pkcs11_find_objects *find_ctx = NULL;
	struct handle_db *object_db = NULL;

	if (!client || ptypes != exp_pt)
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

	/* Search objects only if no operation is on-going */
	if (session_is_active(session)) {
		rc = PKCS11_CKR_OPERATION_ACTIVE;
		goto out;
	}

	if (session->find_ctx) {
		EMSG("Active object search already in progress");
		rc = PKCS11_CKR_FUNCTION_FAILED;
		goto out;
	}

	rc = sanitize_client_object(&req_attrs, template,
				    sizeof(*template) + template->attrs_size,
				    PKCS11_UNDEFINED_ID, PKCS11_UNDEFINED_ID);
	if (rc)
		goto out;

	/* Must zero init the structure */
	find_ctx = TEE_Malloc(sizeof(*find_ctx), TEE_MALLOC_FILL_ZERO);
	if (!find_ctx) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	TEE_Free(template);
	template = NULL;

	switch (get_class(req_attrs)) {
	case PKCS11_CKO_UNDEFINED_ID:
	/* Unspecified class searches among data objects */
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_DATA:
	case PKCS11_CKO_CERTIFICATE:
		break;
	default:
		EMSG("Find object of class %s (%"PRIu32") is not supported",
		     id2str_class(get_class(req_attrs)),
		     get_class(req_attrs));
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	/*
	 * Scan all objects (sessions and persistent ones) and set a list of
	 * candidates that match caller attributes.
	 */

	/* Scan all session objects first */
	TAILQ_FOREACH(sess, get_session_list(session), link) {
		LIST_FOREACH(obj, &sess->object_list, link) {
			/*
			 * Skip all token objects as they could be from
			 * different token which the session does not have
			 * access
			 */
			if (obj->token)
				continue;

			if (!attributes_match_reference(obj->attributes,
							req_attrs))
				continue;

			rc = find_ctx_add(find_ctx,
					  pkcs11_object2handle(obj, session));
			if (rc)
				goto out;
		}
	}

	object_db = get_object_handle_db(session);

	/* Scan token objects */
	LIST_FOREACH(obj, &session->token->object_list, link) {
		uint32_t handle = 0;
		bool new_load = false;

		if (!obj->attributes) {
			rc = load_persistent_object_attributes(obj);
			if (rc)
				return PKCS11_CKR_GENERAL_ERROR;

			new_load = true;
		}

		if (!obj->attributes ||
		    check_access_attrs_against_token(session,
						     obj->attributes) ||
		    !attributes_match_reference(obj->attributes, req_attrs)) {
			if (new_load)
				release_persistent_object_attributes(obj);

			continue;
		}

		/* Resolve object handle for object */
		handle = pkcs11_object2handle(obj, session);
		if (!handle) {
			handle = handle_get(object_db, obj);
			if (!handle) {
				rc = PKCS11_CKR_DEVICE_MEMORY;
				goto out;
			}
		}

		rc = find_ctx_add(find_ctx, handle);
		if (rc)
			goto out;
	}

	find_ctx->attributes = req_attrs;
	req_attrs = NULL;
	session->find_ctx = find_ctx;
	find_ctx = NULL;
	rc = PKCS11_CKR_OK;

out:
	TEE_Free(req_attrs);
	TEE_Free(template);
	release_find_obj_context(find_ctx);

	return rc;
}

enum pkcs11_rc entry_find_objects(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_find_objects *ctx = NULL;
	uint8_t *out_handles = NULL;
	size_t out_count = 0;
	size_t count = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	out_count = out->memref.size / sizeof(uint32_t);
	out_handles = out->memref.buffer;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	ctx = session->find_ctx;

	if (!ctx)
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	for (count = 0; ctx->next < ctx->count && count < out_count;
	     ctx->next++, count++)
		TEE_MemMove(out_handles + count * sizeof(uint32_t),
			    ctx->handles + ctx->next, sizeof(uint32_t));

	/* Update output buffer according the number of handles provided */
	out->memref.size = count * sizeof(uint32_t);

	DMSG("PKCS11 session %"PRIu32": finding objects", session->handle);

	return PKCS11_CKR_OK;
}

void release_session_find_obj_context(struct pkcs11_session *session)
{
	release_find_obj_context(session->find_ctx);
	session->find_ctx = NULL;
}

enum pkcs11_rc entry_find_objects_final(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!session->find_ctx)
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	release_session_find_obj_context(session);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_get_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	struct pkcs11_object *obj = NULL;
	uint32_t object_handle = 0;
	char *cur = NULL;
	size_t len = 0;
	char *end = NULL;
	bool attr_sensitive = 0;
	bool attr_type_invalid = 0;
	bool buffer_too_small = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	/* Iterate over attributes and set their values */
	/*
	 * 1. If the specified attribute (i.e., the attribute specified by the
	 * type field) for the object cannot be revealed because the object is
	 * sensitive or unextractable, then the ulValueLen field in that triple
	 * is modified to hold the value PKCS11_CK_UNAVAILABLE_INFORMATION.
	 *
	 * 2. Otherwise, if the specified value for the object is invalid (the
	 * object does not possess such an attribute), then the ulValueLen field
	 * in that triple is modified to hold the value
	 * PKCS11_CK_UNAVAILABLE_INFORMATION.
	 *
	 * 3. Otherwise, if the pValue field has the value NULL_PTR, then the
	 * ulValueLen field is modified to hold the exact length of the
	 * specified attribute for the object.
	 *
	 * 4. Otherwise, if the length specified in ulValueLen is large enough
	 * to hold the value of the specified attribute for the object, then
	 * that attribute is copied into the buffer located at pValue, and the
	 * ulValueLen field is modified to hold the exact length of the
	 * attribute.
	 *
	 * 5. Otherwise, the ulValueLen field is modified to hold the value
	 * PKCS11_CK_UNAVAILABLE_INFORMATION.
	 */
	cur = (char *)template + sizeof(struct pkcs11_object_head);
	end = cur + template->attrs_size;

	for (; cur < end; cur += len) {
		struct pkcs11_attribute_head *cli_ref = (void *)cur;
		struct pkcs11_attribute_head cli_head = { };
		void *data_ptr = NULL;

		/* Make copy of header so that is aligned properly. */
		TEE_MemMove(&cli_head, cli_ref, sizeof(cli_head));

		len = sizeof(*cli_ref) + cli_head.size;

		/* We don't support getting value of indirect templates */
		if (pkcs11_attr_has_indirect_attributes(cli_head.id)) {
			attr_type_invalid = 1;
			continue;
		}

		/* Check 1. */
		if (!attribute_is_exportable(&cli_head, obj)) {
			cli_head.size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			TEE_MemMove(&cli_ref->size, &cli_head.size,
				    sizeof(cli_head.size));
			attr_sensitive = 1;
			continue;
		}

		/* Get real data pointer from template data */
		data_ptr = cli_head.size ? cli_ref->data : NULL;

		/*
		 * We assume that if size is 0, pValue was NULL, so we return
		 * the size of the required buffer for it (3., 4.)
		 */
		rc = get_attribute(obj->attributes, cli_head.id, data_ptr,
				   &cli_head.size);
		/* Check 2. */
		switch (rc) {
		case PKCS11_CKR_OK:
			break;
		case PKCS11_RV_NOT_FOUND:
			cli_head.size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			attr_type_invalid = 1;
			break;
		case PKCS11_CKR_BUFFER_TOO_SMALL:
			if (data_ptr)
				buffer_too_small = 1;
			break;
		default:
			rc = PKCS11_CKR_GENERAL_ERROR;
			goto out;
		}

		TEE_MemMove(&cli_ref->size, &cli_head.size,
			    sizeof(cli_head.size));
	}

	/*
	 * If case 1 applies to any of the requested attributes, then the call
	 * should return the value CKR_ATTRIBUTE_SENSITIVE. If case 2 applies to
	 * any of the requested attributes, then the call should return the
	 * value CKR_ATTRIBUTE_TYPE_INVALID. If case 5 applies to any of the
	 * requested attributes, then the call should return the value
	 * CKR_BUFFER_TOO_SMALL. As usual, if more than one of these error codes
	 * is applicable, Cryptoki may return any of them. Only if none of them
	 * applies to any of the requested attributes will CKR_OK be returned.
	 */

	rc = PKCS11_CKR_OK;
	if (attr_sensitive)
		rc = PKCS11_CKR_ATTRIBUTE_SENSITIVE;
	if (attr_type_invalid)
		rc = PKCS11_CKR_ATTRIBUTE_TYPE_INVALID;
	if (buffer_too_small)
		rc = PKCS11_CKR_BUFFER_TOO_SMALL;

	/* Move updated template to out buffer */
	TEE_MemMove(out->memref.buffer, template, out->memref.size);

	DMSG("PKCS11 session %"PRIu32": get attributes %#"PRIx32,
	     session->handle, object_handle);

out:
	TEE_Free(template);

	return rc;
}

enum pkcs11_rc entry_get_object_size(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	uint32_t object_handle = 0;
	struct pkcs11_object *obj = NULL;
	uint32_t obj_size = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	if (out->memref.size != sizeof(uint32_t))
		return PKCS11_CKR_ARGUMENTS_BAD;

	obj_size = ((struct obj_attrs *)obj->attributes)->attrs_size +
		   sizeof(struct obj_attrs);
	TEE_MemMove(out->memref.buffer, &obj_size, sizeof(obj_size));

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_set_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	struct pkcs11_object *obj = NULL;
	struct obj_attrs *head = NULL;
	uint32_t object_handle = 0;
	enum processing_func function = PKCS11_FUNCTION_MODIFY;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	/* Only session objects can be modified during a read-only session */
	if (object_is_token(obj->attributes) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't modify persistent object in a RO session");
		rc = PKCS11_CKR_SESSION_READ_ONLY;
		goto out;
	}

	/*
	 * Only public objects can be modified unless normal user is logged in
	 */
	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc) {
		rc = PKCS11_CKR_USER_NOT_LOGGED_IN;
		goto out;
	}

	/* Objects with PKCS11_CKA_MODIFIABLE as false aren't modifiable */
	if (!object_is_modifiable(obj->attributes)) {
		rc = PKCS11_CKR_ACTION_PROHIBITED;
		goto out;
	}

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * Prepare a clean initial state (@head) for the template. Helps in
	 * removing any duplicates or inconsistent values from the
	 * template.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, function,
					     PKCS11_CKM_UNDEFINED_ID,
					     PKCS11_CKO_UNDEFINED_ID);
	if (rc)
		goto out;

	/* Check the attributes in @head to see if they are modifiable */
	rc = check_attrs_against_modification(session, head, obj, function);
	if (rc)
		goto out;

	/*
	 * All checks complete. The attributes in @head have been checked and
	 * can now be used to set/modify the object attributes.
	 */
	rc = modify_attributes_list(&obj->attributes, head);
	if (rc)
		goto out;

	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		rc = update_persistent_object_attributes(obj);
		if (rc)
			goto out;
	}

	DMSG("PKCS11 session %"PRIu32": set attributes %#"PRIx32,
	     session->handle, object_handle);

out:
	TEE_Free(head);
	TEE_Free(template);
	return rc;
}

enum pkcs11_rc entry_copy_object(struct pkcs11_client *client, uint32_t ptypes,
				 TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	struct obj_attrs *head = NULL;
	struct obj_attrs *head_new = NULL;
	size_t template_size = 0;
	struct pkcs11_object *obj = NULL;
	uint32_t object_handle = 0;
	uint32_t obj_handle = 0;
	enum processing_func function = PKCS11_FUNCTION_COPY;
	enum pkcs11_class_id class = PKCS11_CKO_UNDEFINED_ID;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	/* Only session objects can be modified during a read-only session */
	if (object_is_token(obj->attributes) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't modify persistent object in a RO session");
		rc = PKCS11_CKR_SESSION_READ_ONLY;
		goto out;
	}

	/*
	 * Only public objects can be modified unless normal user is logged in
	 */
	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc) {
		rc = PKCS11_CKR_USER_NOT_LOGGED_IN;
		goto out;
	}

	/* Objects with PKCS11_CKA_COPYABLE as false can't be copied */
	if (!object_is_copyable(obj->attributes)) {
		rc = PKCS11_CKR_ACTION_PROHIBITED;
		goto out;
	}

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * Prepare a clean initial state (@head) for the template. Helps in
	 * removing any duplicates or inconsistent values from the
	 * template.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, function,
					     PKCS11_CKM_UNDEFINED_ID,
					     PKCS11_CKO_UNDEFINED_ID);
	if (rc)
		goto out;

	/* Check the attributes in @head to see if they are modifiable */
	rc = check_attrs_against_modification(session, head, obj, function);
	if (rc)
		goto out;

	class = get_class(obj->attributes);

	if (class == PKCS11_CKO_SECRET_KEY ||
	    class == PKCS11_CKO_PRIVATE_KEY) {
		/*
		 * If CKA_EXTRACTABLE attribute in passed template (@head) is
		 * modified to CKA_FALSE, CKA_NEVER_EXTRACTABLE should also
		 * change to CKA_FALSE in copied obj. So, add it to the
		 * passed template.
		 */
		uint8_t bbool = 0;
		uint32_t size = sizeof(bbool);

		rc = get_attribute(head, PKCS11_CKA_EXTRACTABLE, &bbool, &size);
		if (!rc && !bbool) {
			rc = add_attribute(&head, PKCS11_CKA_NEVER_EXTRACTABLE,
					   &bbool, sizeof(uint8_t));
			if (rc)
				goto out;
		}
		rc = PKCS11_CKR_OK;
	}

	/*
	 * All checks have passed. Create a copy of the serialized buffer which
	 * holds the object attributes in @head_new for the new object
	 */
	template_size = sizeof(*obj->attributes) + obj->attributes->attrs_size;
	head_new = TEE_Malloc(template_size, TEE_MALLOC_FILL_ZERO);
	if (!head_new) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	TEE_MemMove(head_new, obj->attributes, template_size);

	/*
	 * Modify the copied attribute @head_new based on the template @head
	 * given by the callee
	 */
	rc = modify_attributes_list(&head_new, head);
	if (rc)
		goto out;

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head_new, including the key value and are assumed
	 * reliable. Now need to register it and get a handle for it.
	 */
	rc = create_object(session, head_new, &obj_handle);
	if (rc)
		goto out;

	/*
	 * Now obj_handle (through the related struct pkcs11_object
	 * instance) owns the serialized buffer that holds the object
	 * attributes. We clear reference in head to NULL as the serializer
	 * object is now referred from obj_handle. This allows smooth pass
	 * through free at function exit.
	 */
	head_new = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": copy object %#"PRIx32,
	     session->handle, obj_handle);

out:
	TEE_Free(head_new);
	TEE_Free(head);
	TEE_Free(template);
	return rc;
}
