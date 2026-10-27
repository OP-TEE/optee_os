// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>
#include <kernel/delay.h>
#include <trace.h>

#include "iris.h"

#define IRIS_CLK_SETTLE_US			1U

#define TZ_BASE		IRIS_WRAPPER_TZ_REG_BASE
#define TOP_BASE	IRIS_WRAPPER_TOP_REG_BASE

#define WRAPPER_TZ_XTSS_SW_RESET		(TZ_BASE + 0x1000)
#define WRAPPER_XTSS_SW_RESET_BIT		BIT(0)

#define WRAPPER_TZ_SEC_CPA_START_ADDR		(TZ_BASE + 0x1020)
#define WRAPPER_TZ_SEC_CPA_END_ADDR		(TZ_BASE + 0x1024)
#define WRAPPER_TZ_SEC_FW_START_ADDR		(TZ_BASE + 0x1028)
#define WRAPPER_TZ_SEC_FW_END_ADDR		(TZ_BASE + 0x102c)
#define WRAPPER_TZ_SEC_NONPIX_START_ADDR	(TZ_BASE + 0x1030)
#define WRAPPER_TZ_SEC_NONPIX_END_ADDR		(TZ_BASE + 0x1034)

#define WRAPPER_TZ_CP_OVERRIDE			(TZ_BASE + 0x1104)
#define WRAPPER_TZ_CP_VP8_SECURE_OVERRIDE_DEC	(TZ_BASE + 0x1188)
#define WRAPPER_TZ_CP_VP9_SECURE_OVERRIDE_DEC	(TZ_BASE + 0x118c)

#define WRAPPER_TZ_VCODEC0_SEC_SID_E_SECURE_OVERRIDE	(TZ_BASE + 0x1148)

#define WRAPPER_TZ_SEC_THRESHOLD_HEVC		(TZ_BASE + 0x1150)
#define WRAPPER_TZ_SEC_THRESHOLD_H264		(TZ_BASE + 0x1154)
#define WRAPPER_TZ_SEC_THRESHOLD_NON_VCL_HEVC	(TZ_BASE + 0x116c)
#define WRAPPER_TZ_SEC_THRESHOLD_NON_VCL_H264	(TZ_BASE + 0x1170)
#define WRAPPER_TZ_SEC_DS_THRESHOLD		(TZ_BASE + 0x1184)

#define WRAPPER_VCODEC0_SEC_SID_0_SECURE	(TOP_BASE + 0x1000)
#define WRAPPER_VCODEC0_SEC_SID_1_SECURE	(TOP_BASE + 0x1004)
#define WRAPPER_VCODEC0_SEC_SID_2_SECURE	(TOP_BASE + 0x1008)
#define WRAPPER_VCODEC0_SEC_SID_3_SECURE	(TOP_BASE + 0x100c)
#define WRAPPER_VCODEC0_SEC_SID_4_SECURE	(TOP_BASE + 0x1010)
#define WRAPPER_VCODEC0_SEC_SID_5_SECURE	(TOP_BASE + 0x1014)
#define WRAPPER_VCODEC0_SEC_SID_6_SECURE	(TOP_BASE + 0x1018)
#define WRAPPER_VCODEC0_SEC_SID_7_SECURE	(TOP_BASE + 0x101c)
#define WRAPPER_VCODEC0_SEC_SID_8_SECURE	(TOP_BASE + 0x1040)
#define WRAPPER_VCODEC0_SEC_SID_9_SECURE	(TOP_BASE + 0x1044)
#define WRAPPER_VCODEC0_SEC_SID_A_SECURE	(TOP_BASE + 0x1048)
#define WRAPPER_VCODEC0_SEC_SID_B_SECURE	(TOP_BASE + 0x104c)
#define WRAPPER_VCODEC0_SEC_SID_C_SECURE	(TOP_BASE + 0x1050)
#define WRAPPER_VCODEC0_SEC_SID_D_SECURE	(TOP_BASE + 0x1054)
#define WRAPPER_VCODEC0_SEC_SID_E_SECURE	(TOP_BASE + 0x1058)
#define WRAPPER_VCODEC0_SEC_SID_F_SECURE	(TOP_BASE + 0x105c)

#define CP_START		0x00000000
#define CP_SIZE			0x25800000
#define CP_NONPIXEL_START	0x01000000
#define CP_NONPIXEL_SIZE	0x24800000

static void iris_program_core_thresholds(vaddr_t iris_base)
{
	io_write32(iris_base + WRAPPER_TZ_SEC_THRESHOLD_HEVC, 1344);
	io_write32(iris_base + WRAPPER_TZ_SEC_THRESHOLD_H264, 270);
	io_write32(iris_base + WRAPPER_TZ_SEC_THRESHOLD_NON_VCL_HEVC, 3800);
	io_write32(iris_base + WRAPPER_TZ_SEC_THRESHOLD_NON_VCL_H264, 12600);
	io_write32(iris_base + WRAPPER_TZ_SEC_DS_THRESHOLD, 3);
}

static void iris_program_core_sid_regs(vaddr_t iris_base)
{
	io_write32(iris_base + WRAPPER_TZ_CP_VP8_SECURE_OVERRIDE_DEC, 0x0);
	io_write32(iris_base + WRAPPER_TZ_CP_VP9_SECURE_OVERRIDE_DEC, 0x0);

	io_write32(iris_base + WRAPPER_TZ_CP_OVERRIDE, 0x0);
	io_write32(iris_base + WRAPPER_TZ_VCODEC0_SEC_SID_E_SECURE_OVERRIDE,
		   0x1);

	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_0_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_1_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_2_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_3_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_4_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_5_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_6_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_7_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_8_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_9_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_A_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_B_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_C_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_D_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_E_SECURE, 0x0);
	io_write32(iris_base + WRAPPER_VCODEC0_SEC_SID_F_SECURE, 0x0);
}

static void iris_program_sec_sid_registers(vaddr_t iris_base)
{
	iris_program_core_thresholds(iris_base);
	iris_program_core_sid_regs(iris_base);
}

static void iris_program_mem_regions(vaddr_t iris_base,
				     const struct qcom_pas_data *data)
{
	io_write32(iris_base + WRAPPER_TZ_SEC_FW_START_ADDR, 0x0);
	io_write32(iris_base + WRAPPER_TZ_SEC_FW_END_ADDR, data->fw_size);

	io_write32(iris_base + WRAPPER_TZ_SEC_CPA_START_ADDR, CP_START);
	io_write32(iris_base + WRAPPER_TZ_SEC_CPA_END_ADDR, CP_START + CP_SIZE);

	io_write32(iris_base + WRAPPER_TZ_SEC_NONPIX_START_ADDR,
		   CP_NONPIXEL_START);
	io_write32(iris_base + WRAPPER_TZ_SEC_NONPIX_END_ADDR,
		   CP_NONPIXEL_START + CP_NONPIXEL_SIZE);
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	vaddr_t iris_base = 0;

	if (!data->fw_base) {
		EMSG("iris: FW not loaded");
		return TEE_ERROR_NO_DATA;
	}

	if (!data->fw_size || data->fw_size > CP_NONPIXEL_START) {
		EMSG("Iris: firmware size %#zx outside the CP layout",
		     data->fw_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	iris_base = io_pa_or_va(&data->base, data->size);
	if (!iris_base)
		return TEE_ERROR_GENERIC;

	udelay(IRIS_CLK_SETTLE_US);

	if (!(io_read32(iris_base + WRAPPER_TZ_XTSS_SW_RESET) &
	      WRAPPER_XTSS_SW_RESET_BIT)) {
		DMSG("iris: subsystem already running, skipping bring-up");
		return TEE_SUCCESS;
	}

	iris_program_mem_regions(iris_base, data);

	iris_program_sec_sid_registers(iris_base);

	io_write32(iris_base + WRAPPER_TZ_XTSS_SW_RESET, 0);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_shutdown(struct qcom_pas_data *data)
{
	vaddr_t iris_base = 0;
	uint32_t reg = 0;

	iris_base = io_pa_or_va(&data->base, data->size);
	if (!iris_base)
		return TEE_ERROR_GENERIC;

	reg = io_read32(iris_base + WRAPPER_TZ_XTSS_SW_RESET);
	if (reg & WRAPPER_XTSS_SW_RESET_BIT) {
		EMSG("iris: subsystem not running, skipping shutdown");
		return TEE_SUCCESS;
	}

	reg |= WRAPPER_XTSS_SW_RESET_BIT;
	io_write32(iris_base + WRAPPER_TZ_XTSS_SW_RESET, reg);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	if (power_on)
		return iris_fw_start(data);

	return iris_fw_shutdown(data);
}

const struct qcom_pas_ops iris_ops = {
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
