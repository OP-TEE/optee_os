// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2019 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
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

#if defined(CFG_MX7)
		reg = io_read32(anatop_addr + OFFSET_DIGPROG_IMX7D);
#elif defined(CFG_MX6SL)
		reg = io_read32(anatop_addr + OFFSET_DIGPROG_IMX6SL);
#else
		reg = io_read32(anatop_addr + OFFSET_DIGPROG);
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

bool soc_is_imx6sl(void)
{
	return imx_soc_type() == SOC_MX6SL;
}

bool soc_is_imx6sll(void)
{
	return imx_soc_type() == SOC_MX6SLL;
}

bool soc_is_imx6sx(void)
{
	return imx_soc_type() == SOC_MX6SX;
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

bool soc_is_imx6(void)
{
	return ((imx_soc_type() == SOC_MX6SX) ||
			(imx_soc_type() == SOC_MX6UL) ||
			(imx_soc_type() == SOC_MX6ULL) ||
			(imx_soc_type() == SOC_MX6DL) ||
			(imx_soc_type() == SOC_MX6Q));
}

bool soc_is_imx7ds(void)
{
	return imx_soc_type() == SOC_MX7D;
}

