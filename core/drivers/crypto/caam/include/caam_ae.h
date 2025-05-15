/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2024 NXP
 */
#ifndef __CAAM_AE_H__
#define __CAAM_AE_H__

#include <caam_common.h>

#if defined(CFG_NXP_CAAM_AE_CCM_DRV) || defined(CFG_NXP_CAAM_AE_GCM_DRV)
/*
 * Initialize the Authentication Encryption module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_ae_init(vaddr_t ctrl_addr __unused);
#else
static inline enum caam_status caam_ae_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_AE_CCM_DRV || CFG_NXP_CAAM_AE_GCM_DRV */
#endif /* __CAAM_AE_H__ */
