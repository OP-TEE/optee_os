// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <trace.h>
#include "ramblur_pimem_v3.h"

static TEE_Result ramblur_pimem_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	const fdt32_t *prop = NULL;
	paddr_t vault_base = 0;
	size_t vault_size = 0;
	vaddr_t regs = 0;
	size_t size = 0;
	int vault = 0;
	int len = 0;

	/* Only OP-TEE uses the controller */
	if (dt_map_dev(fdt, node, &regs, &size, DT_MAP_SECURE) < 0)
		return TEE_ERROR_GENERIC;

	prop = fdt_getprop(fdt, node, "memory-region", &len);
	if (!prop || len != (int)sizeof(*prop))
		return TEE_ERROR_BAD_STATE;

	vault = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*prop));
	if (vault < 0 || fdt_reg_info(fdt, vault, &vault_base, &vault_size))
		return TEE_ERROR_BAD_STATE;

	/* TA RAM is the pIMEM window over the vault */
	if (vault_size != CFG_TA_RAM_VA_SIZE) {
		EMSG("pIMEM vault of %#zx bytes for %#zx bytes of TA RAM",
		     vault_size, (size_t)CFG_TA_RAM_VA_SIZE);
		return TEE_ERROR_BAD_STATE;
	}

	DMSG("Ramblur pIMEM from DT: vault %#" PRIxPA " size %#zx", vault_base,
	     vault_size);

	return ramblur_pimem_v3_init(regs, vault_base, vault_size);
}

static const struct dt_device_match ramblur_pimem_match_table[] = {
	{ .compatible = "qcom,ramblur-pimem-v3" },
	{ }
};

DEFINE_DT_DRIVER(ramblur_pimem_dt_driver) = {
	.name = "qcom-ramblur-pimem-v3",
	.type = DT_DRIVER_NOTYPE,
	.match_table = ramblur_pimem_match_table,
	.probe = ramblur_pimem_probe,
};
