/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "object.h"
#include "pkcs11_token.h"
#include "pkcs11_attributes.h"
#include "processing.h"
#include "serializer.h"
#include "sks_helpers.h"

uint32_t entry_import_object(int teesess,
			     TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_sobj_head *head;
	struct sks_object_head *template = NULL;
	size_t template_size;
	uint32_t obj_handle;

	/*
	 * Collect the arguments of the request
	 */

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(uint32_t))
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &session_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_sks_attributes(&ctrlargs, &template))
		return SKS_BAD_PARAM;

	template_size = sizeof(*template) + template->blobs_size;

	/* Check session/token state against object import */
	session = get_pkcs_session(session_handle);
	if (!session || session->tee_session != teesess) {
		rv = SKS_INVALID_SESSION;
		goto bail;
	}

	if (check_pkcs_session_processing_state(session,
						PKCS11_SESSION_READY)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto bail;
	}

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temorary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     SKS_FUNCTION_IMPORT);
	TEE_Free(template);
	template = NULL;
	if (rv)
		goto bail;

	/*
	 * Check target object attributes match target processing
	 * Check target object attributes match token state
	 */
	rv = check_created_attrs_against_processing(SKS_PROC_RAW_IMPORT, head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * Execute the target processing and add value as attribute SKS_VALUE.
	 * Raw import => key value in clear already as attribute SKS_VALUE.
	 *
	 * Here we only check attribute that attribute SKS_VALUE is defined.
	 * TODO: check value size? check SKS_VALUE_LEN? check SKS_CHECKSUM.
	 */
	rv = serial_get_attribute_ptr(head, SKS_VALUE, NULL, NULL);
	if (rv)
		goto bail;

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head, including the key value and are assume
	 * reliable. Now need to register it and get a handle for it.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct sks_object instance)
	 * owns the serialised buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

bail:
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}