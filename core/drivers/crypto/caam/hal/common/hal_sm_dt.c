// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2024 NXP
 *
 * Brief   CAAM Secure Memory Hardware Abstraction Layer.
 */

#include <caam_common.h>
#include <caam_hal_sm.h>
#include <kernel/dt.h>
#include <libfdt.h>

static const char *dt_sm_match_table = {
	"fsl,imx6q-caam-sm",
};

void caam_hal_sm_get_base_dt(void *fdt, vaddr_t *sm_base)
{
	int node = 0;
	int ret = 0;
	size_t size = 0;

	*sm_base = 0;

	node = fdt_node_offset_by_compatible(fdt, 0, dt_sm_match_table);

	if (node < 0) {
		HAL_TRACE("CAAM Node not found err = 0x%X", node);
		return;
	}

	/* Map the device in the system if not already present */
	ret = dt_map_dev(fdt, node, sm_base, &size, DT_MAP_AUTO);
	if (ret < 0) {
		HAL_TRACE("Cannot map node 0x%X", node);
		return;
	}
}
