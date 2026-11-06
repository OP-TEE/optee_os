// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/delay.h>
#include <trace.h>
#include <util.h>

#include "qdsp6ss.h"

#define QDSP6SS_BOOT_CORE_START_EN	BIT(0)
#define QDSP6SS_BOOT_CMD_START		BIT(0)
#define QDSP6SS_BOOT_STATUS_DONE	BIT(0)

void qdsp6ss_core_start(vaddr_t qdsp6ss)
{
	io_setbits32(qdsp6ss + QDSP6SS_BOOT_CORE_START,
		     QDSP6SS_BOOT_CORE_START_EN);
}

TEE_Result qdsp6ss_boot_fsm(vaddr_t qdsp6ss, uint32_t timeout_us)
{
	uint64_t timeout = 0;

	io_write32(qdsp6ss + QDSP6SS_BOOT_CMD, QDSP6SS_BOOT_CMD_START);

	timeout = timeout_init_us(timeout_us);
	while (!timeout_elapsed(timeout)) {
		if (io_read32(qdsp6ss + QDSP6SS_BOOT_STATUS) &
		    QDSP6SS_BOOT_STATUS_DONE)
			return TEE_SUCCESS;

		udelay(10);
	}

	EMSG("QDSP6SS boot FSM timed out");

	return TEE_ERROR_TIMEOUT;
}
