/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_CIPHER_ALGORITHMS_H_
#define SE050_CIPHER_ALGORITHMS_H_

#include <tee_api_types.h>

#if defined(CFG_NXP_SE05X_CTR_DRV)
TEE_Result se050_aes_ctr_allocate(void **ctx);
#else
static inline TEE_Result se050_aes_ctr_allocate(void **ctx __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif

#endif /* SE050_CIPHER_ALGORITHMS_H_ */
