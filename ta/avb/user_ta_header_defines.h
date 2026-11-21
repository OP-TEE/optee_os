/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */

#ifndef __USER_TA_HEADER_DEFINES_H
#define __USER_TA_HEADER_DEFINES_H

#include <ta_avb.h>

#define TA_UUID				TA_AVB_UUID

/*
 * Keep the instance, crashed or not, so that TA_AVB_CMD_LOCK_BOOT_STATE
 * holds until the TEE restarts.
 */
#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION | \
					 TA_FLAG_INSTANCE_KEEP_ALIVE | \
					 TA_FLAG_INSTANCE_KEEP_CRASHED)

#define TA_STACK_SIZE			(16 * 1024)
#define TA_DATA_SIZE			(16 * 1024)

#define TA_VERSION			"1.0"

#define TA_DESCRIPTION			"Android Verfied Boot"

#endif /*__USER_TA_HEADER_DEFINES_H*/
