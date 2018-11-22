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

static int imx_cpu_type = -1;
static int imx_soc_revision = -1;

#define CPU_TYPE(reg)		((reg & 0x00FF0000) >> 16)
#define SOC_REV_MAJOR(reg)	(((reg & 0x0000FF00) >> 8) + 1)
#define SOC_REV_MINOR(reg)	(reg & 0x0000000F)

static void imx_digproc(void)
{
	uint32_t digprog = 0;
	vaddr_t __maybe_unused anatop_addr = 0;

#if defined(CFG_MX7ULP)
	digprog = SOC_MX7ULP << 16;
#elif defined(CFG_IMX8QX)
	digprog = SOC_MX8QX << 16;
#else
	anatop_addr = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);

	if (!anatop_addr)
		return;

	digprog = io_read32(anatop_addr + DIGPROG_OFFSET);
#endif
	/* Set the CPU type */
	imx_cpu_type = CPU_TYPE(digprog);

#ifdef CFG_MX7
	imx_soc_revision = digprog & 0xFF;
#else
	/* Set the SOC revision: = (Major + 1)[11:4] | (Minor[3:0]) */
	imx_soc_revision =
		(SOC_REV_MAJOR(digprog) << 4) | SOC_REV_MINOR(digprog);
#endif
}

static uint32_t imx_soc_rev_major(void)
{
	if (imx_soc_revision < 0)
		imx_digproc();

	return imx_soc_revision >> 4;
}

static uint32_t imx_soc_type(void)
{
	if (imx_cpu_type < 0)
		imx_digproc();

	return imx_cpu_type;
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

bool soc_is_imx7ulp(void)
{
	return imx_soc_type() == SOC_MX7ULP;
}
