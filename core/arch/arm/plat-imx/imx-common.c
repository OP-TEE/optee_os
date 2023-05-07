// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2019, 2021 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <config.h>
#include <console.h>
#include <io.h>
#include <imx.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

#define SOC_TYPE(reg)	       (((reg) & (0x00FF0000)) >> 16)
#define SOC_REV_MAJOR(reg)     (((reg) & (0x0000FF00)) >> 8)
#define SOC_REV_MINOR(reg)     ((reg) & (0x0000000F))
#define SOC_REV_MINOR_MX7(reg) ((reg) & (0x000000FF))

static uint32_t imx_digprog;

#ifdef ANATOP_BASE
uint32_t imx_get_digprog(void)
{
	vaddr_t addr = 0;

	if (imx_digprog)
		return imx_digprog;

	addr = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC, 0x1000);
	if (!addr)
		return 0;

	imx_digprog = io_read32(addr + DIGPROG_OFFSET);

#ifdef CFG_MX8MQ
	/*
	 * On the i.MX8MQ, the minor revision number must be updated to make
	 * the difference between B0 chip and the newer chips.
	 */
	addr = core_mmu_get_va(OCOTP_BASE, MEM_AREA_IO_SEC, OCOTP_SIZE);
	if (!addr)
		return 0;

	if (io_read32(addr + OCOTP_SW_INFO_B1) == OCOTP_SW_MAGIC_B1)
		imx_digprog |= BIT32(0);
#endif /* CFG_MX8MQ */

	return imx_digprog;
}
#else  /* ANATOP_BASE */
uint32_t imx_get_digprog(void)
{
	if (imx_digprog)
		return imx_digprog;

	if (IS_ENABLED(CFG_MX7ULP))
		imx_digprog = SOC_MX7ULP << 16;
	else if (IS_ENABLED(CFG_MX8QX))
		imx_digprog = SOC_MX8QX << 16;
	else if (IS_ENABLED(CFG_MX8QM))
		imx_digprog = SOC_MX8QM << 16;
	else if (IS_ENABLED(CFG_MX8DXL))
		imx_digprog = SOC_MX8DXL << 16;
	else if (IS_ENABLED(CFG_MX8ULP))
		imx_digprog = SOC_MX8ULP << 16;
	else if (IS_ENABLED(CFG_MX93))
		imx_digprog = SOC_MX93 << 16;

	return imx_digprog;
}
#endif /* ANATOP_BASE */

uint32_t imx_soc_rev_major(void)
{
	if (imx_digprog == 0)
		imx_get_digprog();

	return SOC_REV_MAJOR(imx_digprog);
}

uint32_t imx_soc_rev_minor(void)
{
	if (imx_digprog == 0)
		imx_get_digprog();

	if (IS_ENABLED(CFG_MX7))
		return SOC_REV_MINOR_MX7(imx_digprog);
	else
		return SOC_REV_MINOR(imx_digprog);
}

uint32_t imx_soc_type(void)
{
	if (imx_digprog == 0)
		imx_get_digprog();

	return SOC_TYPE(imx_digprog);
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
	return (imx_soc_type() == SOC_MX6Q) && (imx_soc_rev_major() == 0);
}

bool soc_is_imx6dqp(void)
{
	return (imx_soc_type() == SOC_MX6Q) && (imx_soc_rev_major() == 1);
}

bool soc_is_imx6(void)
{
	uint32_t soc = imx_soc_type();

	return (soc == SOC_MX6SLL) || (soc == SOC_MX6SL) ||
	       (soc == SOC_MX6D) || (soc == SOC_MX6SX) ||
	       (soc == SOC_MX6UL) || (soc == SOC_MX6ULL) ||
	       (soc == SOC_MX6DL) || (soc == SOC_MX6Q);
}

bool soc_is_imx7ds(void)
{
	return imx_soc_type() == SOC_MX7D;
}

bool soc_is_imx7ulp(void)
{
	return imx_soc_type() == SOC_MX7ULP;
}

bool soc_is_imx8mq(void)
{
	return imx_soc_type() == SOC_MX8M && imx_soc_rev_major() == 0x40;
}

bool soc_is_imx8mm(void)
{
	return imx_soc_type() == SOC_MX8M && imx_soc_rev_major() == 0x41;
}

bool soc_is_imx8mn(void)
{
	return imx_soc_type() == SOC_MX8M && imx_soc_rev_major() == 0x42;
}

bool soc_is_imx8mp(void)
{
	return imx_soc_type() == SOC_MX8M && imx_soc_rev_major() == 0x43;
}

bool soc_is_imx8m(void)
{
	return soc_is_imx8mq() || soc_is_imx8mm() || soc_is_imx8mn() ||
	       soc_is_imx8mp();
}

bool soc_is_imx8mq_b0_layer(void)
{
	if (soc_is_imx8mq() && imx_soc_rev_minor() == 0x0)
		return true;
	else
		return false;
}
