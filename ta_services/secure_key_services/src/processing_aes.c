/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <compiler.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "sks_helpers.h"

uint32_t tee_init_ctr_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size)
{
	struct serialargs args;
	uint32_t rv;
	/* CTR parameters */
	uint32_t incr_counter;
	void *counter_bits;

	serialargs_init(&args, proc_params, params_size);

	rv = serialargs_get(&args, &incr_counter, sizeof(uint32_t));
	if (rv)
		goto bail;

	rv = serialargs_get_ptr(&args, &counter_bits, 16);
	if (rv)
		goto bail;

	if (incr_counter != 1) {
		DMSG("Supports only 1 bit increment counter: %d",
						incr_counter);
		rv = SKS_INVALID_PROC_PARAM;
		goto bail;
	}

	TEE_CipherInit(session->tee_op_handle, counter_bits, 16);

	rv = SKS_OK;

bail:
	return rv;
}

void tee_release_ctr_operation(struct pkcs11_session *session __unused)
{
	return;
}
