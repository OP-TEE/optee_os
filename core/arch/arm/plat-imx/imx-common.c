/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017 NXP
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

#include <console.h>
#include <io.h>
#include <imx.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

static uint32_t imx_digproc(void)
{
	static uint32_t reg;
	vaddr_t anatop_addr;

	if (!reg) {
		anatop_addr = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);

		/* TODO: Handle SL here */
#ifdef CFG_MX7
		reg = read32(anatop_addr + OFFSET_DIGPROG_IMX7D);
#else
		reg = read32(anatop_addr + OFFSET_DIGPROG);
#endif
	}

	return reg;
}

static uint32_t imx_soc_rev_major(void)
{
	return ((imx_digproc() & 0xff00) >> 8) + 1;
}

uint32_t imx_soc_type(void)
{
	return (imx_digproc() >> 16) & 0xff;
}

bool soc_is_imx6ul(void)
{
	return imx_soc_type() == SOC_MX6UL;
}

bool soc_is_imx6ull(void)
{
	return imx_soc_type() == SOC_MX6ULL;
}

bool soc_is_imx6sdl(void)
{
	return imx_soc_type() == SOC_MX6DL;
}

bool soc_is_imx6dq(void)
{
	return (imx_soc_type() == SOC_MX6Q) && (imx_soc_rev_major() == 1);
}

bool soc_is_imx6dqp(void)
{
	return (imx_soc_type() == SOC_MX6Q) && (imx_soc_rev_major() == 2);
}

bool soc_is_imx7s(void)
{
	vaddr_t addr = core_mmu_get_va(OCOTP_BASE + 0x450, MEM_AREA_IO_SEC);
	uint32_t val = read32(addr);

	if (soc_is_imx7ds()) {
		if (val & 1)
			return true;
		else
			return false;
	}

	return false;
}

bool soc_is_imx7d(void)
{
	vaddr_t addr = core_mmu_get_va(OCOTP_BASE + 0x450, MEM_AREA_IO_SEC);
	uint32_t val = read32(addr);

	if (soc_is_imx7ds()) {
		if (val & 1)
			return false;
		else
			return true;
	}

	return false;
}

bool soc_is_imx7ds(void)
{
	return imx_soc_type() == SOC_MX7D;
}

uint32_t imx_get_src_gpr(int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);

	if (soc_is_imx7d())
		return read32(va + SRC_GPR1_MX7 + cpu * 8 + 4);
	else
		return read32(va + SRC_GPR1 + cpu * 8 + 4);
}

void imx_set_src_gpr(int cpu, uint32_t val)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);

	if (soc_is_imx7d())
		write32(val, va + SRC_GPR1_MX7 + cpu * 8 + 4);
	else
		write32(val, va + SRC_GPR1 + cpu * 8 + 4);
}
