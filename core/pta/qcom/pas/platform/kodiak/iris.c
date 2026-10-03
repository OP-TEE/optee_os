// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "iris.h"
#include "pas_video.h"

#define WRAPPER_IRIS_VERSION		0x0
#define WRAPPER_CPA_START_ADDR		0x1020
#define WRAPPER_CPA_END_ADDR		0x1024
#define WRAPPER_FW_START_ADDR		0x1028
#define WRAPPER_FW_END_ADDR		0x102C
#define WRAPPER_NONPIX_START_ADDR	0x1030
#define WRAPPER_NONPIX_END_ADDR		0x1034
#define WRAPPER_TZ_XTSS_SW_RESET	0x1000
#define WRAPPER_XTSS_SW_RESET_BIT	BIT(0)

/* Secure session registers, relative to IRIS_BASE */
#define CPU_CS_VCICMD			0x000a0020
#define TOP_TZ				0x000c2000
#define TZ_SEC_THRESHOLD_HEVC		(TOP_TZ + 0x04)
#define TZ_SEC_THRESHOLD_H264		(TOP_TZ + 0x08)
#define TZ_SEC_THRESHOLD_MP2		(TOP_TZ + 0x0c)
#define TZ_SEC_THRESHOLD_NON_VCL_HEVC	(TOP_TZ + 0x18)
#define TZ_SEC_THRESHOLD_NON_VCL_H264	(TOP_TZ + 0x1c)
#define TZ_SEC_THRESHOLD_NON_VCL_MP2	(TOP_TZ + 0x20)
#define TZ_SEC_DS_THRESHOLD		(TOP_TZ + 0x24)
#define TZ_SEC_SID_SECURE_OVERRIDE(n)	(TOP_TZ + 0x40 + 4 * (n))
#define TZ_SEC_SID_COUNT		17
#define TZ_CP_OVERRIDE			(TOP_TZ + 0x90)
#define TZ_CP_VP8_SECURE_OVERRIDE_DEC	(TOP_TZ + 0x98)
#define TZ_CP_VP9_SECURE_OVERRIDE_DEC	(TOP_TZ + 0x9c)

/*
 * Content protection (CP) windows in the device address space of the core,
 * end exclusive: the CP window starts at 0 and holds the firmware, the CP
 * non-pixel window lies inside it, above the firmware. This is the layout
 * Linux passes to the stock firmware for SC7280.
 */
#define IRIS_CP_END			0x25800000
#define IRIS_CP_NONPIX_START		0x01000000
#define IRIS_CP_NONPIX_END		0x25800000

static struct pas_video_seed iris_seed;

/* Stream IDs given a secure override */
static const uint8_t iris_secure_sids[] = { 0xf, 0x1, 0x7 };

/* Secure session settings, as the stock firmware programs them */
static TEE_Result iris_program_sec(vaddr_t base)
{
	vaddr_t reg = 0;
	size_t n = 0;

	io_write32(base + TZ_CP_OVERRIDE, 0);
	for (n = 0; n < TZ_SEC_SID_COUNT; n++)
		io_write32(base + TZ_SEC_SID_SECURE_OVERRIDE(n), 0);

	io_write32(base + TZ_SEC_DS_THRESHOLD, 3);
	io_write32(base + TZ_SEC_THRESHOLD_HEVC, 1344);
	io_write32(base + TZ_SEC_THRESHOLD_H264, 270);
	io_write32(base + TZ_SEC_THRESHOLD_MP2, 46);
	io_write32(base + TZ_SEC_THRESHOLD_NON_VCL_HEVC, 3800);
	io_write32(base + TZ_SEC_THRESHOLD_NON_VCL_H264, 12600);
	io_write32(base + TZ_SEC_THRESHOLD_NON_VCL_MP2, 1600);
	io_write32(base + TZ_CP_VP8_SECURE_OVERRIDE_DEC, 0);
	io_write32(base + TZ_CP_VP9_SECURE_OVERRIDE_DEC, 0);

	for (n = 0; n < ARRAY_SIZE(iris_secure_sids); n++) {
		reg = base + TZ_SEC_SID_SECURE_OVERRIDE(iris_secure_sids[n]);
		io_write32(reg, 1);
		/* The write can be lost; the stock firmware reads it back */
		if (io_read32(reg) != 1) {
			EMSG("Iris: SID %#x secure override not set",
			     iris_secure_sids[n]);
			return TEE_ERROR_GENERIC;
		}
	}

	io_write32(base + CPU_CS_VCICMD, 1);
	if (io_read32(base + CPU_CS_VCICMD) != 1) {
		EMSG("Iris: VCICMD not set");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

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

static TEE_Result iris_reset_cpu(struct qcom_pas_data *data)
{
	vaddr_t base = 0;

	if (iris_check_fw_size(data))
		return TEE_ERROR_BAD_PARAMETERS;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	base += IRIS_WRAPPER_TOP_TZ_REG_BASE;

	io_write32(base + WRAPPER_FW_START_ADDR, 0);
	io_write32(base + WRAPPER_FW_END_ADDR, data->fw_size);
	io_write32(base + WRAPPER_CPA_START_ADDR, 0);
	io_write32(base + WRAPPER_CPA_END_ADDR, IRIS_CP_END);
	io_write32(base + WRAPPER_NONPIX_START_ADDR, IRIS_CP_NONPIX_START);
	io_write32(base + WRAPPER_NONPIX_END_ADDR, IRIS_CP_NONPIX_END);
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

static TEE_Result iris_fw_init_image(struct qcom_pas_data *data __unused,
				     const void *metadata, size_t size)
{
	return pas_video_find_seed(metadata, size, &iris_seed);
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = 0;

	res = iris_check_fw_size(data);
	if (res) {
		pas_video_clear_seed(&iris_seed);
		return res;
	}

	res = pas_video_fill_seed(data, &iris_seed);
	if (res) {
		EMSG("Iris: cannot fill the firmware seed: %#"PRIx32, res);
		return res;
	}

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	/* The settings are retained, so start programs them, resume does not */
	res = iris_program_sec(base);
	if (res)
		return res;

	return iris_reset_cpu(data);
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	if (power_on)
		return iris_reset_cpu(data);

	return iris_fw_shutdown(data);
}

const struct qcom_pas_ops iris_ops = {
	.fw_init_image = iris_fw_init_image,
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
