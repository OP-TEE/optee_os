// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2013, ARM Ltd
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <compiler.h>
#include <console.h>
#include <io.h>
#include <stdint.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/delay.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <arm32.h>

#define REG_CPUCFG_RES0             (0x0000)
#define REG_CPUCFG_CPU_RST(cpu)     (0x0040 + (cpu) * (0x0040))
#define REG_CPUCFG_GEN_CTRL         (0x0184)
#define REG_CPUCFG_PRIV0            (0x01a4)
#define REG_CPUCFG_DBG_CTRL1        (0x01e4)
#define REG_PRCM_CPU_PWROFF         (0x0100)
#define REG_PRCM_CPU_PWR_CLAMP(cpu) (0x0140 + (cpu) * (0x0004))

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
#ifdef CFG_BOOT_SECONDARY_REQUEST
	case PSCI_CPU_ON:
		return 0;
#endif

	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

#ifdef CFG_BOOT_SECONDARY_REQUEST
int psci_cpu_on(uint32_t core_idx, uint32_t entry,
		uint32_t context_id)
{
	vaddr_t base = (vaddr_t)phys_to_virt(SUNXI_PRCM_BASE, MEM_AREA_IO_SEC,
					     SUNXI_PRCM_REG_SIZE);
	vaddr_t cpucfg = (vaddr_t)phys_to_virt(SUNXI_CPUCFG_BASE,
					       MEM_AREA_IO_SEC,
					       SUNXI_CPUCFG_REG_SIZE);
	uint32_t tmpff;
	uint32_t val;

	assert(base);
	assert(cpucfg);

	if ((core_idx == 0) || (core_idx >= CFG_TEE_CORE_NB_CORE))
		return PSCI_RET_INVALID_PARAMETERS;

	/* set secondary cores' NS entry addresses */
	boot_set_core_ns_entry(core_idx, entry, context_id);

	val = virt_to_phys((void *)TEE_TEXT_VA_START);

	/* set entry address */
	DMSG("set entry address for CPU %d", core_idx);
	io_write32(cpucfg + REG_CPUCFG_PRIV0, val);

	/* assert reset on target CPU */
	DMSG("assert reset on target CPU %d", core_idx);
	io_write32(cpucfg + REG_CPUCFG_CPU_RST(core_idx), 0);

	/* invalidate L1 cache */
	DMSG("invalidate L1 cache for CPU %d", core_idx);
	io_clrbits32(cpucfg + REG_CPUCFG_GEN_CTRL, BIT32(core_idx));

	/* lock CPU (Disable external debug access) */
	DMSG("lock CPU %d", core_idx);
	io_clrbits32(cpucfg + REG_CPUCFG_DBG_CTRL1, BIT32(core_idx));

	/* release clamp */
	DMSG("release clamp for CPU %d", core_idx);
	tmpff = 0x1ff;
	do {
		tmpff >>= 1;
		io_write32(base + REG_PRCM_CPU_PWR_CLAMP(core_idx), tmpff);
	} while (tmpff);
	mdelay(10);

	/* clear power gating */
	DMSG("clear power gating for CPU %d", core_idx);
	io_clrbits32(base + REG_PRCM_CPU_PWROFF, BIT32(core_idx));
	udelay(1000);

	/* de-assert reset on target CPU */
	DMSG("de-assert reset on target CPU %d", core_idx);
	io_write32(cpucfg + REG_CPUCFG_CPU_RST(core_idx), 0x03);

	/* unlock CPU (enable external debug access) */
	DMSG("unlock CPU %d", core_idx);
	io_setbits32(cpucfg + REG_CPUCFG_DBG_CTRL1, BIT32(core_idx));

	return PSCI_RET_SUCCESS;
}

int __noreturn psci_cpu_off(void)
{
	uint32_t core_id;
	vaddr_t base = (vaddr_t)phys_to_virt(SUNXI_PRCM_BASE, MEM_AREA_IO_SEC,
					     SUNXI_PRCM_REG_SIZE);
	vaddr_t cpucfg = (vaddr_t)phys_to_virt(SUNXI_CPUCFG_BASE,
					       MEM_AREA_IO_SEC,
					       SUNXI_CPUCFG_REG_SIZE);

	core_id = get_core_pos();

	DMSG("core_id: %" PRIu32, core_id);

#ifdef CFG_PSCI_ARM32
	psci_armv7_cpu_off();
#endif /* CFG_PSCI_ARM32 */

	assert(base);
	assert(cpucfg);

	/* set power gating */
	DMSG("set power gating for cpu %d", core_id);
	io_setbits32(base + REG_PRCM_CPU_PWROFF, BIT32(core_id));

	/* Activate power clamp */
	DMSG("Activate power clamp for cpu %d", core_id);
	io_write32(base + REG_PRCM_CPU_PWR_CLAMP(core_id), 0xff);

	while (true)
		wfi();
}
#endif
