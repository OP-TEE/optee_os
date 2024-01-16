// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 */

#include <compiler.h>
#include <kernel/nv_counter.h>

TEE_Result __weak nv_counter_get_ree_fs(uint32_t *value __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result __weak nv_counter_incr_ree_fs_to(uint32_t value __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
