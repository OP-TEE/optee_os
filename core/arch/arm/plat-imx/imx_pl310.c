/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Peng Fan <peng.fan@nxp.com>
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
#include <arm32.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>

register_phys_mem(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_DEVICE_SIZE);

void arm_cl2_config(vaddr_t pl310_base)
{
	/* Disable PL310 */
	write32(0, pl310_base + PL310_CTRL);

	write32(PL310_TAG_RAM_CTRL_INIT, pl310_base + PL310_TAG_RAM_CTRL);
	write32(PL310_DATA_RAM_CTRL_INIT, pl310_base + PL310_DATA_RAM_CTRL);
	write32(PL310_AUX_CTRL_INIT, pl310_base + PL310_AUX_CTRL);
	write32(PL310_PREFETCH_CTRL_INIT, pl310_base + PL310_PREFETCH_CTRL);
	write32(PL310_POWER_CTRL_INIT, pl310_base + PL310_POWER_CTRL);

	/* invalidate all cache ways */
	arm_cl2_invbyway(pl310_base);
}

void arm_cl2_enable(vaddr_t pl310_base)
{
	uint32_t val;

	/* Enable PL310 ctrl -> only set lsb bit */
	write32(1, pl310_base + PL310_CTRL);

	/* if L2 FLZW enable, enable in L1 */
	val = read32(pl310_base + PL310_AUX_CTRL);
	if (val & 1)
		write_actlr(read_actlr() | (1 << 3));
}

vaddr_t pl310_base(void)
{
	return core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC);
}

