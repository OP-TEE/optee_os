/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __BOOT_MODE_H
#define __BOOT_MODE_H

#include <stdbool.h>
#include <tee_api_types.h>

TEE_Result qcom_is_dload_mode(bool *enabled);

#endif /* __BOOT_MODE_H */
