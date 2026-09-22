// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Owen O'Hehir
 */

#include <arm.h>
#include <cru.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stdint.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CRU_BASE, CRU_SIZE);

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_SYSTEM_OFF:
	case PSCI_SYSTEM_RESET:
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

void psci_system_reset(void)
{
	vaddr_t va_base = (vaddr_t)phys_to_virt_io(CRU_BASE, CRU_SIZE);

	if (!va_base)
		panic("rv1106: CRU not mapped");

	io_write32(va_base + CRU_GLB_SRST_FST, CRU_FSTRST_VAL);
	dsb();
}

void __noreturn psci_system_off(void)
{
	thread_mask_exceptions(THREAD_EXCP_ALL);
	dsb();

	/* No PMIC power-off path on RV1106 boards, next best is WFI */
	while (true)
		wfi();
}
