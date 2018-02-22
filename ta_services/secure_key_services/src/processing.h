/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PROCESSING_H
#define __SKS_TA_PROCESSING_H

#include <tee_internal_api.h>

struct pkcs11_session;
struct sks_object;

/*
 * Entry points frpom SKS TA invocation commands
 */

uint32_t entry_import_object(int teesess, TEE_Param *ctrl,
			     TEE_Param *in, TEE_Param *out);

uint32_t entry_cipher_init(int teesess, TEE_Param *ctrl,
			   TEE_Param *in, TEE_Param *out, int enc);

uint32_t entry_cipher_update(int teesess, TEE_Param *ctrl,
			     TEE_Param *in, TEE_Param *out, int enc);

uint32_t entry_cipher_final(int teesess, TEE_Param *ctrl,
			    TEE_Param *in, TEE_Param *out, int enc);

uint32_t entry_generate_object(int teesess,
			       TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

uint32_t entry_signverify_init(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int sign);

uint32_t entry_signverify_update(int teesess, TEE_Param *ctrl,
				 TEE_Param *in, TEE_Param *out, int sign);

uint32_t entry_signverify_final(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int sign);

/*
 * Crypto algorithm specific
 */
void tee_release_ctr_operation(struct pkcs11_session *session);
uint32_t tee_init_ctr_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size);

#endif /*__SKS_TA_PROCESSING_H*/
