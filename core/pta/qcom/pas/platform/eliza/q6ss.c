// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <drivers/qcom_qdsp6ss.h>
#include <io.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include "q6ss.h"
#include "socinfo.h"

#define QDSP6SS_RET_CFG		0x1c
#define QDSP6SS_BOOT_PARAMS(n)	(0x60 + 4 * (n))

#define BOOT_FSM_TIMEOUT_US	1000000

/* Chip family of the SM7750, which the DSP device tree images select on */
#define CHIP_FAMILY_ELIZA	159

/* Clocks set up or core started, and the subsystem not reset since */
static bool needs_reset[QCOM_CLKS_MAX];

vaddr_t q6ss_base(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return 0;

	switch (data->clk_group) {
	case QCOM_CLKS_TURING:
		return base + TURING_QDSP6SS;
	default:
		return 0;
	}
}

static TEE_Result q6ss_set_dtb_params(vaddr_t q6ss, paddr_t dtb,
				      size_t dtb_size)
{
	struct qcom_socinfo info = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t chip_ver = 0;
	uint32_t plat_ver = 0;

	res = qcom_socinfo_read(&info);
	if (res)
		return res;

	chip_ver = SHIFT_U32((info.version >> 16) & 0xff, 8) |
		   (info.version & 0xff);
	plat_ver = SHIFT_U32((info.platform_version >> 16) & 0xff, 8) |
		   (info.platform_version & 0xff);

	io_write32(q6ss + QDSP6SS_BOOT_PARAMS(0), (uint32_t)dtb);
	io_write32(q6ss + QDSP6SS_BOOT_PARAMS(1), (uint64_t)dtb >> 32);
	io_write32(q6ss + QDSP6SS_BOOT_PARAMS(2),
		   SHIFT_U32(CHIP_FAMILY_ELIZA, 16) | (info.id & 0xffff));
	io_write32(q6ss + QDSP6SS_BOOT_PARAMS(3), chip_ver);
	io_write32(q6ss + QDSP6SS_BOOT_PARAMS(4),
		   SHIFT_U32(info.platform & 0xff, 24) |
		   SHIFT_U32(info.platform_subtype & 0xff, 16) | plat_ver);
	io_write32(q6ss + QDSP6SS_BOOT_PARAMS(5), dtb_size);
	dsb();

	DMSG("DSP DTB %#"PRIxPA" size %zu chip %"PRIu32" v%#"PRIx32
	     " platform %"PRIu32".%"PRIu32" v%#"PRIx32, dtb, dtb_size,
	     info.id, chip_ver, info.platform, info.platform_subtype,
	     plat_ver);

	return TEE_SUCCESS;
}

TEE_Result q6ss_shutdown(struct qcom_pas_data *data)
{
	TEE_Result res = qcom_clock_pas_reset(data->clk_group);

	if (!res)
		needs_reset[data->clk_group] = false;

	return res;
}

static TEE_Result q6ss_dtb_start(struct qcom_pas_data *data)
{
	vaddr_t q6ss = q6ss_base(data);

	if (!q6ss)
		return TEE_ERROR_GENERIC;

	needs_reset[data->clk_group] = true;

	return q6ss_set_dtb_params(q6ss, data->fw_base, data->fw_size);
}

/* The PAS core shuts the image down first (depends_on) */
static TEE_Result q6ss_dtb_shutdown(struct qcom_pas_data *data)
{
	if (!needs_reset[data->clk_group])
		return TEE_SUCCESS;

	return q6ss_shutdown(data);
}

const struct qcom_pas_ops q6ss_dtb_ops = {
	.fw_start = q6ss_dtb_start,
	.fw_shutdown = q6ss_dtb_shutdown,
};

TEE_Result q6ss_boot(vaddr_t q6ss, bool start_core)
{
	/* The EVB and its selection must land before the FSM runs */
	dsb();
	io_write32(q6ss + QDSP6SS_RET_CFG, 0);
	if (start_core)
		qcom_qdsp6ss_core_start(q6ss);

	return qcom_qdsp6ss_boot_fsm(q6ss, BOOT_FSM_TIMEOUT_US);
}
