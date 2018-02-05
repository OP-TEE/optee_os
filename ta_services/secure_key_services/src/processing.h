/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PROCESSING_H
#define __SKS_TA_PROCESSING_H

#include <tee_internal_api.h>

struct pkcs11_session;

/*
 * Entry points frpom SKS TA invocation commands
 */

uint32_t entry_import_object(int teesess, TEE_Param *ctrl,
			     TEE_Param *in, TEE_Param *out);

#endif /*__SKS_TA_PROCESSING_H*/
