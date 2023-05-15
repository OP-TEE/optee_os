/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Pengutronix, Rouven Czerwinski <entwicklung@pengutronix.de>
 */
#ifndef __CAAM_BLOB_H__
#define __CAAM_BLOB_H__

#include <caam_common.h>

#ifdef CFG_NXP_CAAM_BLOB_DRV
/*
 * Initialize the BLOB module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_blob_mkvb_init(vaddr_t baseaddr);
#else
static inline enum caam_status caam_blob_mkvb_init(vaddr_t baseaddr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_BLOB_DRV */

#endif /* __CAAM_BLOB_H__ */
