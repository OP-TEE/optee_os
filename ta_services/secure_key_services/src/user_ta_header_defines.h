/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <sks_ta.h>

#define TA_UUID				TA_SKS_UUID

#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
						TA_FLAG_MULTI_SESSION | \
						TA_FLAG_EXEC_DDR | \
						TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE			(2 * 1024)
#define TA_DATA_SIZE			(16 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "Secure key services trusted application" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0000 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
