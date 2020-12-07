// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

/*
 * Small pseudo-TA to trigger deferred works.
 */

#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <kernel/delay.h>
#include <kernel/deferred_work.h>
#include <pta_dw.h>
#include <stdio.h>
#include <tee_api_defines.h>
#include <trace.h>

#define TA_NAME "dw"

/*
 * Trusted Application Entry Points
 */

static TEE_Result dw_invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				    uint32_t param_types __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	switch (cmd_id) {
	case DW_PTA_EXEC_ALL_DW:
		return deferred_work_do_all();
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_DEFERRED_WORK_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = dw_invoke_command);
