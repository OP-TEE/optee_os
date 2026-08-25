// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <qfprom_target.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "qfprom_hal.h"
#include "qfprom_priv.h"

TEE_Result qfprom_write_set_clock_settings(void)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	vaddr_t cfg_rcgr = gcc_base + GCC_SEC_CTRL_CFG_RCGR;
	vaddr_t cmd_rcgr = gcc_base + GCC_SEC_CTRL_CMD_RCGR;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t blow_timer_value = 0;

	res = qcom_clock_set_rate(cfg_rcgr, cmd_rcgr, QFPROM_CLOCK_DIVIDE);
	if (res != TEE_SUCCESS)
		return res;

	blow_timer_value = (QFPROM_BLOW_TIMER_CLK_FREQ_MHZ_X10 *
			    QFPROM_FUSE_BLOW_TIME_IN_US + 5) / 10;

	hal_qfprom_set_blow_timer(blow_timer_value & 0xFFF);
	hal_qfprom_set_accel(QFPROM_ACCEL_VALUE);

	return TEE_SUCCESS;
}

TEE_Result qfprom_write_reset_clock_settings(void)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	vaddr_t cfg_rcgr = gcc_base + GCC_SEC_CTRL_CFG_RCGR;
	vaddr_t cmd_rcgr = gcc_base + GCC_SEC_CTRL_CMD_RCGR;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = qcom_clock_set_rate(cfg_rcgr, cmd_rcgr, 0);
	if (res != TEE_SUCCESS)
		return res;

	hal_qfprom_set_blow_timer(0);

	hal_qfprom_set_accel(QFPROM_ACCEL_RESET_VALUE);

	return TEE_SUCCESS;
}

TEE_Result qfprom_acquire_hw_mutex(void)
{
	uint64_t timer = timeout_init_us(QFPROM_HW_MUTEX_TIMEOUT_US);
	struct qfprom_context *qfprom_ctx = qfprom_get_context();
	uint32_t read_val = 0;

	while (true) {
		io_write32(qfprom_ctx->mutex_reg_va, QFPROM_HW_MUTEX_PID);
		dsb();

		read_val = io_read32(qfprom_ctx->mutex_reg_va);
		if (read_val == QFPROM_HW_MUTEX_PID)
			return TEE_SUCCESS;

		if (timeout_elapsed(timer)) {
			EMSG("QFPROM HW mutex acquisition timeout after %u us",
			     QFPROM_HW_MUTEX_TIMEOUT_US);
			return TEE_ERROR_BUSY;
		}

		udelay(1);
	}
}

TEE_Result qfprom_release_hw_mutex(void)
{
	struct qfprom_context *qfprom_ctx = qfprom_get_context();

	io_write32(qfprom_ctx->mutex_reg_va, 0);
	dsb();

	return TEE_SUCCESS;
}
