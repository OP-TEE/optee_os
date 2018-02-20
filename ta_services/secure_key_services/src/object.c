/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <sks_internal_abi.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "sks_helpers.h"

/*
 * A database for the objects loaded in the TA.
 * TODO: move object db to session or token.
 */
static struct handle_db object_handle_db = HANDLE_DB_INITIALIZER;

struct sks_object *object_get_tee_handle(uint32_t ck_handle,
					 struct pkcs11_session *session)
{
	int handle = (int)ck_handle;
	struct sks_object *obj = handle_lookup(&object_handle_db, handle);

	if (obj->session_owner != session)
		return NULL;

	return obj;
}

/* Currently handle pkcs11 sessions and tokens */

static inline struct object_list *get_session_objects(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_get_session_objects(ck_session);
}

static struct ck_token *get_session_token(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_session2token(ck_session);
}

static struct ck_token *get_object_token(struct sks_object *obj)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = obj->session_owner;

	return pkcs11_session2token(ck_session);
}

/* Release resources of a non persistent object */
static void cleanup_volatile_object(struct sks_object *obj)
{
	if (!obj)
		return;

	if (obj->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj->key_handle);

	handle_put(&object_handle_db, obj->ck_handle);
	TEE_Free(obj->attributes);
	TEE_Free(obj);
}

/* Release resources of a persistent object including volatile resources */
static void cleanup_persistent_object(struct sks_object *obj)
{
	if (!obj)
		return;

	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseAndDeletePersistentObject1(obj->attribs_hdl);

	destroy_object_uuid(get_session_token(obj->session_owner), obj);

	cleanup_volatile_object(obj);
}

/*
 * Destroy an object
 *
 * @session - session requesting object destruction
 * @hld - object handle returned to hte client
 */
uint32_t destroy_object(struct pkcs11_session *session,
			  struct sks_object *obj,
			  bool session_only)
{
#ifdef DEBUG
	trace_attributes("[destroy]", obj->attributes);
#endif

	/*
	 * Objects are reachable only from their context.
	 * We only support pkcs11 session for now: check object token id.
	 */
	if (get_object_token(obj) != session->token)
		return SKS_BAD_PARAM;

	/* Non persistent object are reachable from their session */
	if (obj->attribs_hdl == TEE_HANDLE_NULL &&
	    obj->session_owner != session)
		return SKS_INVALID_OBJECT;

	LIST_REMOVE(obj, link);

	if (session_only) {
		/* Destroy object due to session closure */
		cleanup_volatile_object(obj);
		return SKS_OK;
	}

	/* Destroy target object (persistent or not) */
	if (get_bool(obj->attributes, SKS_PERSISTENT)) {
		if (unregister_persistent_object(get_object_token(obj),
						  obj->uuid))
			TEE_Panic(0);

		cleanup_persistent_object(obj);
	} else {
		cleanup_volatile_object(obj);
	}

	return SKS_OK;
}

/*
 * Create an object
 * - Allocate and fill a 'struct sks_object' instance
 * - Output a sks object handle
 */
uint32_t create_object(void *session, struct sks_attrs_head *head,
		       uint32_t *out_handle)
{
	uint32_t rv;
	TEE_Result res = TEE_SUCCESS;
	struct sks_object *obj;
	int obj_handle;

#ifdef DEBUG
	trace_attributes("[create]", head);
#endif

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */

	obj = TEE_Malloc(sizeof(struct sks_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return SKS_MEMORY;

	obj_handle = handle_get(&object_handle_db, obj);
	if (obj_handle < 0 || obj_handle > 0x7FFFFFFF) {
		TEE_Free(obj);
		return SKS_FAILED;
	}

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;
	obj->ck_handle = (uint32_t)obj_handle;
	obj->session_owner = session;

	if (get_bool(obj->attributes, SKS_PERSISTENT)) {
		/*
		 * Get an ID for the persistent object
		 * Create the file
		 * Register the object in the persistent database
		 * (move the full sequence to persisent_db.c?)
		 */
		size_t size = attributes_size(obj->attributes);

		rv = create_object_uuid(get_session_token(session), obj);
		if (rv)
			goto bail;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->uuid, sizeof(TEE_UUID),
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE |
						 TEE_DATA_FLAG_ACCESS_WRITE_META |
						 TEE_DATA_FLAG_OVERWRITE, /* TODO: don't overwrite! */
						 TEE_HANDLE_NULL,
						 obj->attributes, size,
						 &obj->attribs_hdl);
		if (res) {
			rv = tee2sks_error(res);
			goto bail;
		}

		rv = register_persistent_object(get_session_token(session),
						obj->uuid);
		if (rv)
			goto bail;
	} else {
		rv = SKS_OK;
	}

	LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	*out_handle = obj->ck_handle;

bail:
	if (rv) {
		if (get_bool(obj->attributes, SKS_PERSISTENT))
			cleanup_persistent_object(obj);
		else
			cleanup_volatile_object(obj);
	}

	return rv;
}

uint32_t  entry_destroy_object(int teesess, TEE_Param *ctrl,
			    TEE_Param *in, TEE_Param *out)
{
	struct serialargs ctrlargs;
	uint32_t session_handle;
	uint32_t object_handle;
	struct pkcs11_session *session;
	struct sks_object *object;

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &session_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_next(&ctrlargs, &object_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	session = get_pkcs_session(session_handle);
	if (!session || session->tee_session != teesess)
		return SKS_INVALID_SESSION;

	object = object_get_tee_handle(object_handle, session);
	if (!object || object->session_owner != session)
		return SKS_BAD_PARAM;

	return destroy_object(session, object, false);
}
