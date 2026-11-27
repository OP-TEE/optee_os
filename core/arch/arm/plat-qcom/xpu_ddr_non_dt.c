// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/xpuv4.h>
#include <platform_config.h>
#include <qcom_common.h>
#include <util.h>
#include <xpu_target.h>

/*
 * The DRAM windows, from the target's macros, in address order. With TME-Lite
 * IPC, its carveout sits between DRAM0 and DRAM2; DRAM1 is the second bank.
 */
static const struct xpu4_guard ddr_guards[] = {
	{
		.start = DRAM0_BASE,
		.size = DRAM0_SIZE,
		.mpu_start = DDR_MPU_ADDR_LOW(DRAM0_BASE),
	},
#ifdef CFG_QCOM_TMEL_COM
	{
		.start = TMEL_COM_IPC_BUF_ADDR,
		.size = CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE,
		.mpu_start = DDR_MPU_ADDR_LOW(TMEL_COM_IPC_BUF_ADDR),
	},
#endif
#ifdef DRAM2_BASE
	{
		.start = DRAM2_BASE,
		.size = DRAM2_SIZE,
		.mpu_start = DDR_MPU_ADDR_LOW(DRAM2_BASE),
	},
#endif
	{
		.start = DRAM1_BASE,
		.size = DRAM1_SIZE,
		.mpu_start = DDR_MPU_ADDR_HIGH(DRAM1_BASE),
	},
};

TEE_Result qcom_xpu_get_ddr_guards(const struct xpu4_guard **guards,
				   size_t *count)
{
	*guards = ddr_guards;
	*count = ARRAY_SIZE(ddr_guards);

	return TEE_SUCCESS;
}
