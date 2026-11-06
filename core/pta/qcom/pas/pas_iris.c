// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "pas_iris.h"
#include "pas_video.h"

/* Registers, as offsets from IRIS_BASE */
#define WRAPPER_TZ_XTSS_SW_RESET		0x000c1000
#define WRAPPER_XTSS_SW_RESET_BIT		BIT(0)
#define WRAPPER_TZ_SEC_CPA_START_ADDR		0x000c1020
#define WRAPPER_TZ_SEC_CPA_END_ADDR		0x000c1024
#define WRAPPER_TZ_SEC_FW_START_ADDR		0x000c1028
#define WRAPPER_TZ_SEC_FW_END_ADDR		0x000c102c
#define WRAPPER_TZ_SEC_NONPIX_START_ADDR	0x000c1030
#define WRAPPER_TZ_SEC_NONPIX_END_ADDR		0x000c1034

/*
 * Content protection (CP) windows in the device address space of the core,
 * end exclusive: the CP window starts at 0 and holds the firmware, the CP
 * non-pixel window lies inside it, above the firmware. This is the layout
 * Linux passes to the stock firmware for SC7280 and SM8550 (SA8775P).
 */
#define IRIS_CP_END			0x25800000
#define IRIS_CP_NONPIX_START		0x01000000
#define IRIS_CP_NONPIX_END		0x25800000

/* The firmware must fit below the CP non-pixel window */
static TEE_Result iris_check_fw_size(struct qcom_pas_data *data)
{
	if (!data->fw_size || data->fw_size > IRIS_CP_NONPIX_START) {
		EMSG("Iris: firmware size %#zx outside the CP layout",
		     data->fw_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void iris_program_mem_regions(vaddr_t base,
				     const struct qcom_pas_data *data)
{
	io_write32(base + WRAPPER_TZ_SEC_FW_START_ADDR, 0);
	io_write32(base + WRAPPER_TZ_SEC_FW_END_ADDR, data->fw_size);
	io_write32(base + WRAPPER_TZ_SEC_CPA_START_ADDR, 0);
	io_write32(base + WRAPPER_TZ_SEC_CPA_END_ADDR, IRIS_CP_END);
	io_write32(base + WRAPPER_TZ_SEC_NONPIX_START_ADDR,
		   IRIS_CP_NONPIX_START);
	io_write32(base + WRAPPER_TZ_SEC_NONPIX_END_ADDR, IRIS_CP_NONPIX_END);
}

static const struct pas_iris_write sec_clear[] = {
	PAS_IRIS_WRITE(SS_TZ_CP_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_0_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_1_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_2_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_3_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_4_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_5_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_6_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_7_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_8_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_9_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_A_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_B_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_C_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_D_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_E_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_F_SECURE_OVERRIDE, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_10_SECURE_OVERRIDE, 0),
};

static const struct pas_iris_write sec_thresholds[] = {
	PAS_IRIS_WRITE(SS_TZ_SEC_DS_THRESHOLD, 3),
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_HEVC, 1344),
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_H264, 270),
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_MP2, 46),
};

static const struct pas_iris_write sec_non_vcl_thresholds[] = {
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_NON_VCL_HEVC, 3800),
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_NON_VCL_H264, 12600),
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_NON_VCL_MP2, 1600),
};

static const struct pas_iris_write sec_checks[] = {
	PAS_IRIS_CHECK(SS_TZ_SEC_SID_1_SECURE_OVERRIDE, 1),
	PAS_IRIS_CHECK(SS_TZ_SEC_SID_7_SECURE_OVERRIDE, 1),
};

static TEE_Result iris_write_seq(vaddr_t base, const struct pas_iris_seq *seq)
{
	const struct pas_iris_write *w = seq->writes;
	uint32_t val = 0;
	size_t i = 0;

	for (i = 0; i < seq->count; i++, w++) {
		io_write32(base + w->reg, w->val);
		if (!w->check)
			continue;

		val = io_read32(base + w->reg);
		if (val != w->val) {
			EMSG("Iris: register %#"PRIx32" reads %#"PRIx32
			     ", expected %#"PRIx32, w->reg, val, w->val);
			return TEE_ERROR_GENERIC;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result iris_program_sec_session(vaddr_t base,
					   const struct pas_iris_cfg *cfg)
{
	const struct pas_iris_seq seqs[] = {
		{ sec_clear, ARRAY_SIZE(sec_clear) },
		cfg->after_clear,
		{ sec_thresholds, ARRAY_SIZE(sec_thresholds) },
		cfg->after_thresholds,
		{ sec_non_vcl_thresholds, ARRAY_SIZE(sec_non_vcl_thresholds) },
		cfg->before_checks,
		{ sec_checks, ARRAY_SIZE(sec_checks) },
		cfg->after_checks,
	};
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(seqs); i++) {
		res = iris_write_seq(base, seqs + i);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result iris_reset_cpu(struct qcom_pas_data *data, bool start)
{
	const struct pas_iris_cfg *cfg = data->iris;
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = 0;

	res = iris_check_fw_size(data);
	if (res)
		return res;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	if (cfg && (start || cfg->every_release)) {
		res = iris_program_sec_session(base, cfg);
		if (res)
			return res;
	}

	iris_program_mem_regions(base, data);
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

	reg = io_read32(base + WRAPPER_TZ_XTSS_SW_RESET);
	reg |= WRAPPER_XTSS_SW_RESET_BIT;
	io_write32(base + WRAPPER_TZ_XTSS_SW_RESET, reg);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = iris_check_fw_size(data);
	if (res) {
		pas_video_clear_seed(data);
		return res;
	}

	res = pas_video_fill_seed(data);
	if (res) {
		EMSG("Iris: cannot fill the firmware seed: %#"PRIx32, res);
		return res;
	}

	return iris_reset_cpu(data, true);
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	if (power_on)
		return iris_reset_cpu(data, false);

	return iris_fw_shutdown(data);
}

const struct qcom_pas_ops pas_iris_ops = {
	.fw_init_image = pas_video_find_seed,
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
