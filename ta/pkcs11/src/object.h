/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_OBJECT_H
#define PKCS11_TA_OBJECT_H

#include <pkcs11_ta.h>
#include <sys/queue.h>
#include <tee_internal_api.h>

struct ck_token;
struct obj_attrs;
struct pkcs11_client;
struct pkcs11_session;

/*
 * link: objects are referenced in a double-linked list
 * attributes: pointer to the serialized object attributes
 * key_handle: GPD TEE object handle if used in an operation
 * key_type: GPD TEE key type (shortcut used for processing)
 * token: associated token for the object
 * uuid: object UUID in the persistent database if a persistent object, or NULL
 * attribs_hdl: GPD TEE attributes handles if persistent object
 */
struct pkcs11_object {
	LIST_ENTRY(pkcs11_object) link;
	struct obj_attrs *attributes;
	TEE_ObjectHandle key_handle;
	uint32_t key_type;
	struct ck_token *token;
	TEE_UUID *uuid;
	TEE_ObjectHandle attribs_hdl;
};

LIST_HEAD(object_list, pkcs11_object);

struct pkcs11_object *pkcs11_handle2object(uint32_t client_handle,
					   struct pkcs11_session *session);

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session);

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid,
					  struct ck_token *token);

enum pkcs11_rc create_object(void *session, struct obj_attrs *attributes,
			     uint32_t *handle);

void cleanup_persistent_object(struct pkcs11_object *obj,
			       struct ck_token *token);

void destroy_object(struct pkcs11_session *session,
		    struct pkcs11_object *object, bool session_object_only);

/*
 * Entry function called from the PKCS11 command parser
 */
enum pkcs11_rc entry_create_object(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_destroy_object(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_find_objects_init(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_find_objects(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_find_objects_final(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_get_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_get_object_size(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_set_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_copy_object(struct pkcs11_client *client, uint32_t ptypes,
				 TEE_Param *params);

void release_session_find_obj_context(struct pkcs11_session *session);

#endif /*PKCS11_TA_OBJECT_H*/
