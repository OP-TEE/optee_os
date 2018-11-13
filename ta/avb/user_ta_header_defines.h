/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */

#ifndef __USER_TA_HEADER_DEFINES_H
#define __USER_TA_HEADER_DEFINES_H

#include <ta_avb.h>

#define TA_UUID				TA_AVB_UUID

#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION)

#define TA_STACK_SIZE			(16 * 1024)
#define TA_DATA_SIZE			(16 * 1024)

#endif /*__USER_TA_HEADER_DEFINES_H*/
