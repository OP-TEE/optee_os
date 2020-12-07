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

#if defined(CFG_DEFERRED_WORK_WITH_TESTS)

#define DW_TEST_WORKS_CNT 10

static TEE_Result test_dw_ok(void *data __unused)
{
	return TEE_SUCCESS;
}

static void dw_add_tests(int cnt)
{
	int i;
	char name[32] = { 0 };
	TEE_Result res;

	for (i = 0; i < cnt; ++i) {
		(void)snprintf(name, sizeof(name), "test-dw #%d", i);

		res = deferred_work_add(name, test_dw_ok, NULL);
		if (res != TEE_SUCCESS)
			EMSG("dw <%s> failed to schedule for deferred execution with code 0x%x",
			     name, res);
		else
			IMSG("dw <%s> was scheduled for deferred execution successfully",
			     name);
	}
}
#endif /* CFG_DEFERRED_WORK_WITH_TESTS */

/*
 * Trusted Application Entry Points
 */

static TEE_Result dw_invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				    uint32_t param_types __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused)
{
#if defined(CFG_DEFERRED_WORK_WITH_TESTS)
	static int test_done;

	if (!test_done) {
		dw_add_tests(DW_TEST_WORKS_CNT);
		test_done = 1;
	}
#endif
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
