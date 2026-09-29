/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Vaisala Oyj.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <app_secrets_ta.h>

#define TA_UUID				APP_SECRETS_TA_UUID

#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION)

#define TA_STACK_SIZE			(4 * 1024)
#define TA_DATA_SIZE			(16 * 1024)

#define TA_VERSION			"1.0"

#define TA_DESCRIPTION			"Application Secrets TA"

#endif /* USER_TA_HEADER_DEFINES_H */
