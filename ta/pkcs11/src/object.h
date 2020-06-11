/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_OBJECT_H
#define PKCS11_TA_OBJECT_H

#include <pkcs11_ta.h>
#include <sys/queue.h>
#include <tee_internal_api.h>

struct obj_attrs;
struct pkcs11_client;
struct pkcs11_session;

/*
 * link: objects are referenced in a double-linked list
 * attributes: pointer to the serialized object attributes
 * key_handle: GPD TEE object handle if used in an operation
 * key_type: GPD TEE key type (shortcut used for processing)
 * uuid: object UUID in the persistent database if a persistent object, or NULL
 * attribs_hdl: GPD TEE attributes handles if persistent object
 */
struct pkcs11_object {
	LIST_ENTRY(pkcs11_object) link;
	struct obj_attrs *attributes;
	TEE_ObjectHandle key_handle;
	uint32_t key_type;
	TEE_UUID *uuid;
	TEE_ObjectHandle attribs_hdl;
};

LIST_HEAD(object_list, pkcs11_object);

struct pkcs11_object *pkcs11_handle2object(uint32_t client_handle,
					   struct pkcs11_session *session);

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session);

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid);

enum pkcs11_rc create_object(void *session, struct obj_attrs *attributes,
			     uint32_t *handle);

void destroy_object(struct pkcs11_session *session,
		    struct pkcs11_object *object, bool session_object_only);

/*
 * Entry function called from the PKCS11 command parser
 */
enum pkcs11_rc entry_import_object(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_destroy_object(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params);
#endif /*PKCS11_TA_OBJECT_H*/
