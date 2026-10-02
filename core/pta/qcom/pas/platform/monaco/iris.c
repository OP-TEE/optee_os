// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "iris.h"

/* Register blocks, relative to IRIS_BASE */
#define WRAPPER_TOP			0x000b0000
#define WRAPPER_TZ			0x000c0000
#define TOP_TZ				0x000c2000

#define WRAPPER_SEC_CSR1		(WRAPPER_TOP + 0x1084)
#define WRAPPER_SEC_CSR7		(WRAPPER_TOP + 0x109c)

#define WRAPPER_TZ_XTSS_SW_RESET	(WRAPPER_TZ + 0x1000)
#define WRAPPER_TZ_SEC_CPA_START	(WRAPPER_TZ + 0x1020)
#define WRAPPER_TZ_SEC_CPA_END		(WRAPPER_TZ + 0x1024)
#define WRAPPER_TZ_SEC_FW_START		(WRAPPER_TZ + 0x1028)
#define WRAPPER_TZ_SEC_FW_END		(WRAPPER_TZ + 0x102c)
#define WRAPPER_TZ_SEC_NONPIX_START	(WRAPPER_TZ + 0x1030)
#define WRAPPER_TZ_SEC_NONPIX_END	(WRAPPER_TZ + 0x1034)
#define XTSS_SW_RESET			BIT(0)

#define TZ_SEC_THRESHOLD_HEVC		(TOP_TZ + 0x04)
#define TZ_SEC_THRESHOLD_H264		(TOP_TZ + 0x08)
#define TZ_SEC_THRESHOLD_MP2		(TOP_TZ + 0x0c)
#define TZ_SEC_THRESHOLD_NON_VCL_HEVC	(TOP_TZ + 0x18)
#define TZ_SEC_THRESHOLD_NON_VCL_H264	(TOP_TZ + 0x1c)
#define TZ_SEC_THRESHOLD_NON_VCL_MP2	(TOP_TZ + 0x20)
#define TZ_SEC_DS_THRESHOLD		(TOP_TZ + 0x24)
#define TZ_SEC_THRESHOLD_AV1		(TOP_TZ + 0x2c)
#define TZ_SEC_SID_SECURE_OVERRIDE(n)	(TOP_TZ + 0x40 + 4 * (n))
#define TZ_SEC_SID_COUNT		17
#define TZ_CP_OVERRIDE			(TOP_TZ + 0x90)

/* Stream IDs whose secure override the reference sequence sets */
static const uint8_t iris_secure_sids[] = { 0x1, 0x7, 0xf, 0xc, 0xd, 0xe };

/*
 * Secure session settings, values from the reference sequence. Written on
 * every start: the retained values are not reliable after a warm boot.
 */
static void iris_program_sec(vaddr_t base)
{
	vaddr_t reg = 0;
	size_t n = 0;

	io_write32(base + TZ_CP_OVERRIDE, 0);
	for (n = 0; n < TZ_SEC_SID_COUNT; n++)
		io_write32(base + TZ_SEC_SID_SECURE_OVERRIDE(n), 0);

	io_write32(base + WRAPPER_SEC_CSR1, 1);

	io_write32(base + TZ_SEC_DS_THRESHOLD, 3);
	io_write32(base + TZ_SEC_THRESHOLD_HEVC, 1344);
	io_write32(base + TZ_SEC_THRESHOLD_H264, 270);
	io_write32(base + TZ_SEC_THRESHOLD_MP2, 46);
	io_write32(base + TZ_SEC_THRESHOLD_AV1, 1280);
	io_write32(base + TZ_SEC_THRESHOLD_NON_VCL_HEVC, 3800);
	io_write32(base + TZ_SEC_THRESHOLD_NON_VCL_H264, 12600);
	io_write32(base + TZ_SEC_THRESHOLD_NON_VCL_MP2, 1600);

	for (n = 0; n < ARRAY_SIZE(iris_secure_sids); n++) {
		reg = base + TZ_SEC_SID_SECURE_OVERRIDE(iris_secure_sids[n]);
		io_write32(reg, 1);
		/* The read back is the reference workaround for a lost write */
		if (io_read32(reg) != 1)
			EMSG("SID %#x secure override not set",
			     iris_secure_sids[n]);
	}

	io_write32(base + WRAPPER_SEC_CSR7, 1);
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return TEE_ERROR_GENERIC;

	/* As in the reference, a core already out of reset is left running */
	if (!(io_read32(base + WRAPPER_TZ_XTSS_SW_RESET) & XTSS_SW_RESET))
		return TEE_SUCCESS;

	io_write32(base + WRAPPER_TZ_SEC_FW_START, 0);
	io_write32(base + WRAPPER_TZ_SEC_FW_END, data->fw_size);
	io_write32(base + WRAPPER_TZ_SEC_CPA_START, 0);
	io_write32(base + WRAPPER_TZ_SEC_CPA_END, data->fw_size);
	io_write32(base + WRAPPER_TZ_SEC_NONPIX_START, data->fw_size);
	io_write32(base + WRAPPER_TZ_SEC_NONPIX_END, data->fw_size);

	iris_program_sec(base);

	io_clrbits32(base + WRAPPER_TZ_XTSS_SW_RESET, XTSS_SW_RESET);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_shutdown(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return TEE_ERROR_GENERIC;

	io_setbits32(base + WRAPPER_TZ_XTSS_SW_RESET, XTSS_SW_RESET);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool on)
{
	if (on)
		return iris_fw_start(data);

	return iris_fw_shutdown(data);
}

const struct qcom_pas_ops iris_ops = {
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
