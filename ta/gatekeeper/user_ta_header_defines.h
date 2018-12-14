/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2017, GlobalLogic  */

#ifndef __USER_TA_HEADER_DEFINES_H
#define __USER_TA_HEADER_DEFINES_H

#include <gatekeeper_ipc.h>

#define TA_UUID TA_GATEKEEPER_UUID

#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               (2 * 1024)
#define TA_DATA_SIZE                (32 * 1024)

#endif /* __USER_TA_HEADER_DEFINES_H */
