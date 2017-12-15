/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
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

#ifndef __IMX_PM_H
#define __IMX_PM_H

#include <stdint.h>

#define PM_INFO_MX7_M4_RESERVE0_OFF	0x0
#define PM_INFO_MX7_M4_RESERVE1_OFF	0x4
#define PM_INFO_MX7_M4_RESERVE2_OFF	0x8
#define PM_INFO_MX7_PBASE_OFF		0xc
#define PM_INFO_MX7_ENTRY_OFF		0x10
#define PM_INFO_MX7_RESUME_ADDR_OFF	0x14
#define PM_INFO_MX7_DDR_TYPE_OFF	0x18
#define PM_INFO_MX7_SIZE_OFF		0x1c
#define PM_INFO_MX7_DDRC_P_OFF		0x20
#define PM_INFO_MX7_DDRC_V_OFF		0x24
#define PM_INFO_MX7_DDRC_PHY_P_OFF	0x28
#define PM_INFO_MX7_DDRC_PHY_V_OFF	0x2c
#define PM_INFO_MX7_SRC_P_OFF		0x30
#define PM_INFO_MX7_SRC_V_OFF		0x34
#define PM_INFO_MX7_IOMUXC_GPR_P_OFF	0x38
#define PM_INFO_MX7_IOMUXC_GPR_V_OFF	0x3c
#define PM_INFO_MX7_CCM_P_OFF		0x40
#define PM_INFO_MX7_CCM_V_OFF		0x44
#define PM_INFO_MX7_GPC_P_OFF		0x48
#define PM_INFO_MX7_GPC_V_OFF		0x4c
#define PM_INFO_MX7_SNVS_P_OFF		0x50
#define PM_INFO_MX7_SNVS_V_OFF		0x54
#define PM_INFO_MX7_ANATOP_P_OFF	0x58
#define PM_INFO_MX7_ANATOP_V_OFF	0x5c
#define PM_INFO_MX7_LPSR_P_OFF		0x60
#define PM_INFO_MX7_LPSR_V_OFF		0x64
#define PM_INFO_MX7_GIC_DIST_P_OFF	0x68
#define PM_INFO_MX7_GIC_DIST_V_OFF	0x6c
#define PM_INFO_MX7_TTBR0_OFF		0x70
#define PM_INFO_MX7_TTBR1_OFF		0x74
#define PM_INFO_MX7_DDRC_REG_NUM_OFF	0x78
#define PM_INFO_MX7_DDRC_REG_OFF	0x7C
#define PM_INFO_MX7_DDRC_PHY_REG_NUM_OFF	0x17C
#define PM_INFO_MX7_DDRC_PHY_REG_OFF	0x180

#define MX7_DDRC_NUM			32
#define MX7_DDRC_PHY_NUM		16


#define SUSPEND_OCRAM_SIZE		0x1000
#define LOWPOWER_IDLE_OCRAM_SIZE	0x1000

#define SUSPEND_OCRAM_OFFSET		0x0
#define LOWPOWER_IDLE_OCRAM_OFFSET	0x1000

#ifndef ASM
#include <sm/sm.h>

struct imx7_pm_info {
	uint32_t	m4_reserve0;
	uint32_t	m4_reserve1;
	uint32_t	m4_reserve2;
	paddr_t		pa_base;	/* pa of pm_info */
	uintptr_t	entry;
	paddr_t		tee_resume;
	uint32_t	ddr_type;
	uint32_t	pm_info_size;
	paddr_t		ddrc_pa_base;
	vaddr_t		ddrc_va_base;
	paddr_t		ddrc_phy_pa_base;
	vaddr_t		ddrc_phy_va_base;
	paddr_t		src_pa_base;
	vaddr_t		src_va_base;
	paddr_t		iomuxc_gpr_pa_base;
	vaddr_t		iomuxc_gpr_va_base;
	paddr_t		ccm_pa_base;
	vaddr_t		ccm_va_base;
	paddr_t		gpc_pa_base;
	vaddr_t		gpc_va_base;
	paddr_t		snvs_pa_base;
	vaddr_t		snvs_va_base;
	paddr_t		anatop_pa_base;
	vaddr_t		anatop_va_base;
	paddr_t		lpsr_pa_base;
	vaddr_t		lpsr_va_base;
	paddr_t		gic_pa_base;
	vaddr_t		gic_va_base;
	uint32_t	ttbr0;
	uint32_t	ttbr1;
	uint32_t	ddrc_num;
	uint32_t	ddrc_val[MX7_DDRC_NUM][2];
	uint32_t	ddrc_phy_num;
	uint32_t	ddrc_phy_val[MX7_DDRC_NUM][2];
} __aligned(8);

struct suspend_save_regs {
	uint32_t irq[3];
	uint32_t fiq[3];
	uint32_t und[3];
	uint32_t abt[3];
	uint32_t mon[3];
} __aligned(8);

struct imx7_pm_data {
	uint32_t ddr_type;
	uint32_t ddrc_num;
	uint32_t (*ddrc_offset)[2];
	uint32_t ddrc_phy_num;
	uint32_t (*ddrc_phy_offset)[2];
};

void imx7_suspend(struct imx7_pm_info *info);
void imx7_resume(void);
void ca7_cpu_resume(void);
int imx7_suspend_init(void);
int pm_imx7_iram_tbl_init(void);
int imx7_cpu_suspend(uint32_t power_state, uintptr_t entry,
		     uint32_t context_id, struct sm_nsec_ctx *nsec);
#endif

#endif
