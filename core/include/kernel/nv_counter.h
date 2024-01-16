/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Linaro Limited
 */

#ifndef __KERNEL_NV_COUNTER_H
#define __KERNEL_NV_COUNTER_H

#include <tee_api_types.h>
#include <types_ext.h>

TEE_Result nv_counter_get_ree_fs(uint32_t *value);
TEE_Result nv_counter_incr_ree_fs_to(uint32_t value);

#endif /*__KERNEL_NV_COUNTER_H*/
