/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_qcom_pas.h>

#define TA_UUID				TA_PAS_UUID

#define TA_FLAGS			(TA_FLAG_DEVICE_ENUM | \
					 TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_INSTANCE_KEEP_ALIVE)

/* Provisioned stack size */
#define TA_STACK_SIZE			(4 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE			CFG_PAS_TA_HEAP_SIZE

/* The gpd.ta.version property */
#define TA_VERSION	"1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION	"remote processor firmware management"

#endif /* USER_TA_HEADER_DEFINES_H */
