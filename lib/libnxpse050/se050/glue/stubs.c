// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 *
 * Empty implementation for undefined symbols due to our use case not selecting
 * all the files in the se05 middleware
 */

#include <fsl_sss_se05x_types.h>
#include <stubs.h>

sss_status_t sss_digest_context_init(sss_digest_t *context,
				     sss_session_t *session,
				     sss_algorithm_t algorithm, sss_mode_t mode)
{
	sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;
	sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)session;

	return sss_se05x_digest_context_init(se05x_context, se05x_session,
					     algorithm, mode);
}

sss_status_t sss_digest_init(sss_digest_t *context)
{
	sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;

	return sss_se05x_digest_init(se05x_context);
}

sss_status_t sss_digest_update(sss_digest_t *context, const uint8_t *message,
			       size_t len)
{
	sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;

	return sss_se05x_digest_update(se05x_context, message, len);
}

sss_status_t sss_digest_finish(sss_digest_t *context, uint8_t *digest,
			       size_t *len)
{
	sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;

	return sss_se05x_digest_finish(se05x_context, digest, len);
}

void sss_digest_context_free(sss_digest_t *context)
{
	sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;

	sss_se05x_digest_context_free(se05x_context);
}

sss_status_t sss_digest_one_go(sss_digest_t *context __unused,
			       const uint8_t *message __unused,
			       size_t mlen __unused,
			       uint8_t *digest __unused,
			       size_t *dlen __unused)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_key_store_set_key(sss_key_store_t *keyStore __unused,
				   sss_object_t *keyObject __unused,
				   const uint8_t *data __unused,
				   size_t dlen __unused,
				   size_t bit_len __unused,
				   void *options __unused,
				   size_t olen __unused)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_key_store_get_key(sss_key_store_t *key_store __unused,
				   sss_object_t *key_object __unused,
				   uint8_t *data __unused,
				   size_t *dlen __unused,
				   size_t *bit_len __unused)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_rng_context_init(sss_rng_context_t *context __unused,
				  sss_session_t *session __unused)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_rng_get_random(sss_rng_context_t *context __unused,
				uint8_t *random_data __unused,
				size_t dlen __unused)
{
	return kStatus_SSS_Fail;
}

int sscanf(const char *str __unused, const char *format __unused, ...)
{
	return -1;
}
