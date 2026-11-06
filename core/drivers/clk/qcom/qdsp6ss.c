// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom_qdsp6ss.h>
#include <io.h>
#include <kernel/delay.h>
#include <trace.h>
#include <util.h>

#define QDSP6SS_BOOT_CORE_START_EN	BIT(0)
#define QDSP6SS_BOOT_CMD_START		BIT(0)
#define QDSP6SS_BOOT_STATUS_DONE	BIT(0)

void qcom_qdsp6ss_core_start(vaddr_t qdsp6ss)
{
	io_setbits32(qdsp6ss + QDSP6SS_BOOT_CORE_START,
		     QDSP6SS_BOOT_CORE_START_EN);
}

TEE_Result qcom_qdsp6ss_boot_fsm(vaddr_t qdsp6ss, uint32_t timeout_us)
{
	uint32_t val = 0;

	io_write32(qdsp6ss + QDSP6SS_BOOT_CMD, QDSP6SS_BOOT_CMD_START);

	if (IO_READ32_POLL_TIMEOUT(qdsp6ss + QDSP6SS_BOOT_STATUS, val,
				   val & QDSP6SS_BOOT_STATUS_DONE, 10,
				   timeout_us)) {
		EMSG("QDSP6SS boot FSM timed out");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}
