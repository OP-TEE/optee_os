/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 *
 * Brief   ELE ECC driver TEE Crypto integration.
 */
#ifndef __ECC_H__
#define __ECC_H__

#include <tee_api_types.h>

#ifdef CFG_IMX_ELE_ECC_DRV
/*
 * Initialize the ECC module
 */
TEE_Result imx_ele_ecc_init(void);
#else
static inline TEE_Result imx_ele_ecc_init(void)
{
	return TEE_SUCCESS;
}
#endif /* CFG_IMX_ELE_ECC_DRV */

#endif /* __ECC_H__ */
