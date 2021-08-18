// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */

#include <compiler.h>
#include <stdint.h>
#include "optee_sp_internal_api.h"
#include "optee_sp_user_defines.h"

#ifndef OPTEE_SP_UUID
#error "OPTEE_SP_UUID is not defined in SP"
#endif

#ifndef OPTEE_SP_STACK_SIZE
#error "OPTEE_SP_STACK_SIZE is not defined in SP"
#endif

const struct optee_sp_head sp_head __section(".sp_head") = {
	.uuid = OPTEE_SP_UUID,
	.stack_size = OPTEE_SP_STACK_SIZE,
	.flags = 0,
	.depr_entry = UINT64_MAX
};
