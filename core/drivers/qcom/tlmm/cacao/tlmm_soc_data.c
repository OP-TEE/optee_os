// SPDX-License-Identifier: BSD-2-Clause
/*
 * Cacao TLMM hardware descriptor.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <drivers/qcom/tlmm/tlmm.h>
#include <util.h>

const struct tlmm_desc tlmm_soc_desc = {
	.base            = TLMM_BASE,
	.size            = TLMM_BASE_SIZE,
	.pin_reg_width   = 0x1000,
	.num_tiles       = 1,
	.tile_offsets    = { [0] = 0x100000 },
	.num_gpios       = 132,
	.has_egpio       = true,
	.has_strong_pull = true,
};
