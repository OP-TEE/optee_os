/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2024 NXP
 */
#ifndef __CAAM_AE_H__
#define __CAAM_AE_H__

#include <caam_common.h>

/*
 * Initialize the Authentication Encryption module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_ae_init(vaddr_t ctrl_addr __unused);

#endif /* __CAAM_AE_H__ */
