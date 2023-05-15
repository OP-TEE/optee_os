/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_VERSAL_PM_H__
#define __DRIVERS_VERSAL_PM_H__

#include <tee_api_types.h>
#include <types_ext.h>

TEE_Result versal_soc_version(uint8_t *version);
TEE_Result versal_write_fpga(paddr_t pa);

#endif /*__DRIVERS_VERSAL_PM_H__*/
