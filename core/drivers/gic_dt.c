// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <drivers/gic.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <trace.h>
#include <util.h>

/* The GIC compatibles of the Linux DT binding */
static const char * const gic_compatible[] = {
	"arm,gic-v3",
	"arm,gic-400",
	"arm,cortex-a15-gic",
	"arm,cortex-a9-gic",
	"arm,cortex-a7-gic",
	"arm,cortex-a5-gic",
	"qcom,msm-qgic2",
	NULL
};

/*
 * The first register window is the distributor, the second one the CPU
 * interface (GICv2) or the redistributors (GICv3 and GICv4).
 */
TEE_Result gic_init_from_dt(void)
{
	const char * const *compat = NULL;
	const void *fdt = get_dt();
	paddr_t base[2] = { };
	size_t size[2] = { };
	size_t i = 0;
	int node = -1;

	if (!fdt) {
		EMSG("GIC: no DT");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	for (compat = gic_compatible; *compat && node < 0; compat++)
		node = fdt_node_offset_by_compatible(fdt, -1, *compat);
	if (node < 0) {
		EMSG("GIC: no GIC node in the DT");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	for (i = 0; i < ARRAY_SIZE(base); i++) {
		if (fdt_get_reg_props_by_index(fdt, node, i, &base[i],
					       &size[i])) {
			EMSG("GIC: no register window %zu in the DT", i);
			return TEE_ERROR_BAD_FORMAT;
		}
		if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, base[i], size[i])) {
			EMSG("GIC: cannot map %#"PRIxPA, base[i]);
			return TEE_ERROR_GENERIC;
		}
	}

	DMSG("GIC: bases from DT: %#"PRIxPA" %#"PRIxPA, base[0], base[1]);
	if (IS_ENABLED2(_CFG_ARM_GIC_V3_OR_V4))
		gic_init_v3(0, base[0], base[1]);
	else
		gic_init(base[1], base[0]);

	return TEE_SUCCESS;
}
