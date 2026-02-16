/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _DSP_BOOT_H_
#define _DSP_BOOT_H_

#include <io.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "dsp.h"
#include "pas.h"

/*
 * Compute
 */
#define TURING_QDSP6V68SS_PUB_REG	0x00b00000
#define TURING_QDSP6V68SS_CC_REG	0x00b18000
#define TURING_QDSP6SS_Q6_CC_REG	0x00b40000

static const struct dsp_fw_boot_regs compute_fw_boot_regs = {
	.xo_cbcr = TURING_QDSP6V68SS_CC_REG + 0x54,
	.sleep_cbcr = TURING_QDSP6V68SS_CC_REG + 0x58,
	.core_cbcr = TURING_QDSP6SS_Q6_CC_REG + 0x1040,
	.rst_evb = TURING_QDSP6V68SS_PUB_REG + 0x10,
	.core_start = TURING_QDSP6V68SS_PUB_REG + 0x400,
	.boot_cmd = TURING_QDSP6V68SS_PUB_REG + 0x404,
	.boot_status = TURING_QDSP6V68SS_PUB_REG + 0x408,
};

/*
 * WPSS
 */
#define WPSS_QDSP6V67SS_PUB_REG	0x00000000

static const struct dsp_fw_boot_regs wpss_fw_boot_regs = {
	.xo_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x38,
	.sleep_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x3c,
	.core_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x20,
	.rst_evb = WPSS_QDSP6V67SS_PUB_REG + 0x10,
	.core_start = WPSS_QDSP6V67SS_PUB_REG + 0x400,
	.boot_cmd = WPSS_QDSP6V67SS_PUB_REG + 0x404,
	.boot_status = WPSS_QDSP6V67SS_PUB_REG + 0x408,
};

static inline const struct dsp_fw_boot_regs *dsp_fw_get_boot_regs(uint32_t id)
{
	switch (id) {
	case PAS_ID_WPSS:
		return &wpss_fw_boot_regs;
	case PAS_ID_TURING:
		return &compute_fw_boot_regs;
	default:
		return NULL;
	}
}

#endif /* _DSP_BOOT_H_ */
