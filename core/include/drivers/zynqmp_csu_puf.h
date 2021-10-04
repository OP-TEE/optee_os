/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2021
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef __DRIVERS_ZYNQMP_CSU_PUF_H_
#define __DRIVERS_ZYNQMP_CSU_PUF_H_

#include <tee_api_types.h>

TEE_Result zynqmp_csu_puf_regenerate(void);
void zynqmp_csu_puf_reset(void);

#endif
