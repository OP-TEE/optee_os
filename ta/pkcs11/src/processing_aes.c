// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <tee_internal_api.h>
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
