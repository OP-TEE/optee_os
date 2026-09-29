// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>
#include <string.h>

#include "iris.h"

#define WRAPPER_IRIS_VERSION		0x0
#define WRAPPER_CPA_START_ADDR		0x1020
#define WRAPPER_CPA_END_ADDR		0x1024
#define WRAPPER_FW_START_ADDR		0x1028
#define WRAPPER_FW_END_ADDR		0x102C
#define WRAPPER_NONPIX_START_ADDR	0x1030
#define WRAPPER_NONPIX_END_ADDR		0x1034
#define WRAPPER_TZ_XTSS_SW_RESET	0x1000
#define WRAPPER_XTSS_SW_RESET_BIT	BIT(0)

static TEE_Result iris_reset_cpu(struct qcom_pas_data *data)
{
	vaddr_t base = 0;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	base += IRIS_WRAPPER_TOP_TZ_REG_BASE;

	io_write32(base + WRAPPER_FW_START_ADDR, 0);
	io_write32(base + WRAPPER_FW_END_ADDR, data->fw_size);
	io_write32(base + WRAPPER_CPA_START_ADDR, 0);
	io_write32(base + WRAPPER_CPA_END_ADDR, data->fw_size);
	io_write32(base + WRAPPER_NONPIX_START_ADDR, data->fw_size);
	io_write32(base + WRAPPER_NONPIX_END_ADDR, data->fw_size);
	io_write32(base + WRAPPER_TZ_XTSS_SW_RESET, 0);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_shutdown(struct qcom_pas_data *data)
{
	vaddr_t base = 0;
	uint32_t reg = 0;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	base += IRIS_WRAPPER_TOP_TZ_REG_BASE;

	reg = io_read32(base + WRAPPER_TZ_XTSS_SW_RESET);
	reg |= WRAPPER_XTSS_SW_RESET_BIT;
	io_write32(base + WRAPPER_TZ_XTSS_SW_RESET, reg);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	return iris_reset_cpu(data);
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	if (power_on)
		return iris_reset_cpu(data);

	return iris_fw_shutdown(data);
}

const struct qcom_pas_ops iris_ops = {
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
