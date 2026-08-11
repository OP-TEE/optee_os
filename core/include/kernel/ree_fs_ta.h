/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __KERNEL_REE_FS_TA_H
#define __KERNEL_REE_FS_TA_H

#include <types_ext.h>
#include <tee_api_types.h>

TEE_Result ree_fs_check_update_ta_version(const uint8_t uuid[sizeof(TEE_UUID)],
					  uint32_t version);


#endif /*__KERNEL_REE_FS_TA_H*/
