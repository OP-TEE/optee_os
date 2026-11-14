// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <trace.h>
#include "ramblur_pimem_cfg.h"

/*
 * Only OP-TEE uses the controller, so its node is secure-only and it is the
 * embedded DT that has it.
 */
void ramblur_pimem_get_cfg(struct ramblur_pimem_cfg *cfg)
{
	const void *fdt = get_embedded_dt();
	const fdt32_t *prop = NULL;
	int node = -1;
	int len = 0;

	if (fdt)
		node = fdt_node_offset_by_compatible(fdt, -1,
						     "qcom,ramblur-pimem");
	if (node < 0 || !(fdt_get_status(fdt, node) & DT_STATUS_OK_SEC) ||
	    fdt_get_reg_props_by_index(fdt, node, 0, &cfg->reg_base,
				       &cfg->reg_size))
		panic("No usable Ramblur pIMEM node in the DT");

	prop = fdt_getprop(fdt, node, "memory-region", &len);
	if (!prop || len < (int)sizeof(*prop))
		panic("No Ramblur pIMEM vault in the DT");

	node = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*prop));
	if (node < 0 ||
	    fdt_get_reg_props_by_index(fdt, node, 0, &cfg->vault_base,
				       &cfg->vault_size))
		panic("No Ramblur pIMEM vault in the DT");

	/* TA RAM is the pIMEM window over the vault */
	if (cfg->vault_size != CFG_TA_RAM_VA_SIZE)
		panic("Ramblur pIMEM vault size != TA RAM size");

	DMSG("Ramblur pIMEM from DT: regs %#" PRIxPA " vault %#" PRIxPA
	     " size %#zx", cfg->reg_base, cfg->vault_base, cfg->vault_size);
}
