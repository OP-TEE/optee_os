// SPDX-License-Identifier: BSD-2-Clause
/*
 * LeMans TLMM hardware descriptor.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/tlmm/tlmm.h>
#include <platform_config.h>
#include <util.h>

const struct tlmm_desc tlmm_soc_desc = {
	.base = TLMM_BASE,
	.size = TLMM_BASE_SIZE,
	.pin_reg_width = 0x1000,
	.num_tiles = 1,
	.tile_offsets = { [0] = 0x100000 },
	.num_gpios = 149,
	.has_egpio = true,
	.has_strong_pull = false,
};
