/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_OBJECT_H
#define __SKS_OBJECT_H

#include <sks_internal_abi.h>
#include <sys/queue.h>
#include <tee_internal_api.h>


struct pkcs11_session;

struct sks_object {
	LIST_ENTRY(sks_object) link;
	void *session_owner;
	uint32_t ck_handle;	// TODO: rename client_handle
	/* pointer to the serialized object attributes */
	void *attributes;
	TEE_ObjectHandle key_handle;
	/* These are for persistent/token objects (TODO: move to attributes) */
	void *uuid;
	TEE_ObjectHandle attribs_hdl;
};

LIST_HEAD(object_list, sks_object);

struct sks_object *object_get_tee_handle(uint32_t ck_handle,
					 struct pkcs11_session *session);

/*
 * create_object - create an SKS object from its attributes and value
 *
 * @session - session requesting object creation
 * @attributes - reference to serialized attributes
 * @handle - generated handle for the created object
 */
uint32_t create_object(void *session, struct sks_sobj_head *attributes,
			uint32_t *handle);

/*
 * destroy_object - destroy an SKS object
 *
 * @session - session requesting object destruction
 * @object - reference to the sks object
 * @session_object_only - true is only session object shall be destroyed
 */
uint32_t destroy_object(struct pkcs11_session *session,
			struct sks_object *object,
			bool session_object_only);

uint32_t entry_destroy_object(int teesess, TEE_Param *ctrl,
			      TEE_Param *in, TEE_Param *out);


#endif /*__SKS_OBJECT_H*/
