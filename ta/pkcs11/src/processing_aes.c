// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

enum pkcs11_rc tee_init_ctr_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	/* CTR parameters */
	uint32_t incr_counter = 0;
	void *counter_bits = NULL;

	if (!proc_params)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &incr_counter, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &counter_bits, 16);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (incr_counter != 1) {
		DMSG("Supports only 1 bit increment counter: %"PRIu32,
		     incr_counter);

		return PKCS11_CKR_MECHANISM_PARAM_INVALID;
	}

	TEE_CipherInit(processing->tee_op_handle, counter_bits, 16);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc load_tee_aes_key_attrs(TEE_Attribute **tee_attrs,
					size_t *tee_count,
					struct pkcs11_object *obj)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Attribute *attrs = NULL;

	attrs = TEE_Malloc(1 * sizeof(TEE_Attribute),
			   TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!attrs)
		return PKCS11_CKR_DEVICE_MEMORY;

	rc = pkcs2tee_load_attr(attrs, TEE_ATTR_SECRET_VALUE,
				obj, PKCS11_CKA_VALUE);
	if (rc != PKCS11_CKR_OK) {
		goto error;
	}

	*tee_attrs = attrs;
	*tee_count = 1;

out:
	return rc;
error:
	TEE_Free(attrs);
	goto out;
}
