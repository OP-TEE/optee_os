/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef CHIPINFO_INTERNAL_H
#define CHIPINFO_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <drivers/qcom/chipinfo/chipinfo.h>
#include <drivers/qcom/platforminfo/platforminfodefs.h>

struct chipinfo_ctxt {
	bool initialized;
	enum chipinfo_id chip_id;
	uint32_t version;
	enum chipinfo_family family_id;
	/* Indexed by enum chipinfo_part; non-zero means fused off. */
	uint32_t part_state[CHIPINFO_NUM_PARTS];
	/* Per-instance table, snapshotted from SMEM at init time. */
	struct part_instances part_info[CHIPINFO_MAX_PART_INSTANCES];
	uint32_t num_insts;
};

/*
 * SMEM_HW_SW_BUILD_ID - SMEM item ID for the socinfo item. This value is
 * part of a fixed hardware/firmware ABI and must not be changed.
 */
#define SMEM_HW_SW_BUILD_ID	137U

#endif /* CHIPINFO_INTERNAL_H */
