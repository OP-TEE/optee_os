/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __PTA_REE_SERVICE_H__
#define __PTA_REE_SERVICE_H__

#define PTA_GENERIC_UUID { 0xfeca9a1d, 0x5ff0, 0x4204, { \
			  0xb4, 0x83, 0x34, 0x86, 0x23, 0x71, 0x2d, 0xc9 } }

#define OPTEE_MRC_GENERIC_OPEN			0xFFFFFFF0
#define OPTEE_MRC_GENERIC_CLOSE			0xFFFFFFF1
#define OPTEE_MRC_GENERIC_SERVICE_START 0xFFFFFFF2
#define OPTEE_MRC_GENERIC_SERVICE_STOP  0xFFFFFFF3
#endif
