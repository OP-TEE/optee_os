// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <trace.h>

/*
 * TCSR_PCIE_LINK_CONFIG_MODE holds the PCIe link mode selected by firmware.
 * The value selects one of these topologies:
 *   0 (QMP_PCIE_NORD_MODE_X16)         all ports combined as one x16 PHY
 *   1 (QMP_PCIE_NORD_MODE_X8_X8)       port A as x8, ports B+C+D as x8
 *   2 (QMP_PCIE_NORD_MODE_X8_X4_X4)    port A as x8, port B as x4, ports
 *                                      C+D as x4
 *   3 (QMP_PCIE_NORD_MODE_X8_X4_X2_X2) port A as x8, port B as x4, ports
 *                                      C and D as x2
 */
#define PCIE_LINK_CONFIG_MODE		0x3

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_PCIE_LINK_CONFIG_MODE,
			sizeof(uint32_t));

static TEE_Result qcom_pcie_tcsr_init(void)
{
	vaddr_t va = (vaddr_t)phys_to_virt(TCSR_PCIE_LINK_CONFIG_MODE,
					   MEM_AREA_IO_SEC, sizeof(uint32_t));

	if (!va) {
		EMSG("pcie_tcsr: failed to map TCSR_PCIE_LINK_CONFIG_MODE");
		return TEE_ERROR_GENERIC;
	}

	io_write32(va, PCIE_LINK_CONFIG_MODE);
	DMSG("pcie_tcsr: link config mode set to 0x%x", PCIE_LINK_CONFIG_MODE);

	return TEE_SUCCESS;
}

driver_init(qcom_pcie_tcsr_init);
