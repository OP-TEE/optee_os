/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <trusted_keys.h>

#define TA_UUID				TRUSTED_KEYS_UUID

#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION | \
					 TA_FLAG_DEVICE_ENUM)

#define TA_STACK_SIZE			(4 * 1024)
#define TA_DATA_SIZE			(16 * 1024)

#endif /*USER_TA_HEADER_DEFINES_H*/
