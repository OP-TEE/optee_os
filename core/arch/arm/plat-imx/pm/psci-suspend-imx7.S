/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <generated/imx_pm_asm_defines.h>
#include <imx-regs.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>
#include <platform_config.h>

#define MX7_SRC_GPR1	0x74
#define MX7_SRC_GPR2	0x78
#define GPC_PGC_C0	0x800
#define GPC_PGC_FM	0xa00
#define ANADIG_SNVS_MISC_CTRL	0x380
#define ANADIG_SNVS_MISC_CTRL_SET 0x384
#define ANADIG_SNVS_MISC_CTRL_CLR 0x388
#define ANADIG_DIGPROG	0x800
#define DDRC_STAT	0x4
#define DDRC_PWRCTL	0x30
#define DDRC_PSTAT	0x3fc
#define DDRC_PCTRL_0	0x490
#define DDRC_DFIMISC	0x1b0
#define DDRC_SWCTL	0x320
#define DDRC_SWSTAT	0x324
#define DDRPHY_LP_CON0	0x18

#define CCM_SNVS_LPCG	0x250
#define MX7D_GPC_IMR1	0x30
#define MX7D_GPC_IMR2	0x34
#define MX7D_GPC_IMR3	0x38
#define MX7D_GPC_IMR4	0x3c

/*
 * The code in this file is copied to coherent on-chip ram memory,
 * without any dependency on code/data in tee memory(DDR).
 */
	.section .text.psci.suspend
	.align 3

	.macro	disable_l1_dcache

	/*
	 * flush L1 data cache before clearing SCTLR.C bit.
	 */
	push	{r0 - r10, lr}
	ldr	r1, =dcache_op_all
	mov	r0, #DCACHE_OP_CLEAN_INV
	mov	lr, pc
	bx	r1
	pop	{r0 - r10, lr}

	/* disable d-cache */
	read_sctlr r7
	bic	r7, r7, #SCTLR_C
	write_sctlr r7
	dsb
	isb

	push	{r0 - r10, lr}
	ldr	r1, =dcache_op_all
	mov	r0, #DCACHE_OP_CLEAN_INV
	mov	lr, pc
	bx	r1
	pop	{r0 - r10, lr}

	.endm

	.macro store_ttbr

	/* Store TTBR1 to pm_info->ttbr1 */
	read_ttbr1 r7
	str	r7, [r0, #PM_INFO_MX7_TTBR1_OFF]

	/* Store TTBR0 to pm_info->ttbr1 */
	read_ttbr0 r7
	str	r7, [r0, #PM_INFO_MX7_TTBR0_OFF]

	/* Disable Branch Prediction */
	read_sctlr r6
	bic	r6, r6, #SCTLR_Z
	write_sctlr r6

	/* Flush the BTAC. */
	write_bpiallis

	ldr	r6, =iram_tbl_phys_addr
	ldr	r6, [r6]
	dsb
	isb

	/* Store the IRAM table in TTBR1/0 */
	write_ttbr1 r6
	write_ttbr0 r6

	/* Read TTBCR and set PD0=1 */
	read_ttbcr r6
	orr	r6, r6, #TTBCR_PD0
	write_ttbcr r6

	dsb
	isb

	/* flush the TLB */
	write_tlbiallis
	isb
	write_tlbiall
	isb

	.endm

	.macro restore_ttbr

	/* Enable L1 data cache. */
	read_sctlr r6
	orr	r6, r6, #SCTLR_C
	write_sctlr r6

	dsb
	isb

	/* Restore TTBCR */
	/* Read TTBCR and set PD0=0 */
	read_ttbcr r6
	bic	r6, r6, #TTBCR_PD0
	write_ttbcr r6
	dsb
	isb

	/* flush the TLB */
	write_tlbiallis

	/* Enable Branch Prediction */
	read_sctlr r6
	orr	r6, r6, #SCTLR_Z
	write_sctlr r6

	/* Flush the Branch Target Address Cache (BTAC) */
	write_bpiallis

	/* Restore TTBR1/0, get the origin ttbr1/0 from pm info */
	ldr	r7, [r0, #PM_INFO_MX7_TTBR1_OFF]
	write_ttbr1 r7
	ldr	r7, [r0, #PM_INFO_MX7_TTBR0_OFF]
	write_ttbr0 r7
	isb

	.endm

	.macro ddrc_enter_self_refresh

	ldr	r11, [r0, #PM_INFO_MX7_DDRC_V_OFF]

	/* let DDR out of self-refresh */
	ldr	r7, =0x0
	str	r7, [r11, #DDRC_PWRCTL]

	/* wait rw port_busy clear */
	ldr	r6, =BIT32(16)
	orr	r6, r6, #0x1
1:
	ldr	r7, [r11, #DDRC_PSTAT]
	ands	r7, r7, r6
	bne	1b

	/* enter self-refresh bit 5 */
	ldr	r7, =BIT32(5)
	str	r7, [r11, #DDRC_PWRCTL]

	/* wait until self-refresh mode entered */
2:
	ldr	r7, [r11, #DDRC_STAT]
	and	r7, r7, #0x3
	cmp	r7, #0x3
	bne	2b
3:
	ldr	r7, [r11, #DDRC_STAT]
	ands	r7, r7, #0x20
	beq	3b

	/* disable dram clk */
	ldr	r7, [r11, #DDRC_PWRCTL]
	orr	r7, r7, #BIT32(3)
	str	r7, [r11, #DDRC_PWRCTL]

	.endm

	.macro ddrc_exit_self_refresh

	cmp	r5, #0x0
	ldreq	r11, [r0, #PM_INFO_MX7_DDRC_V_OFF]
	ldrne	r11, [r0, #PM_INFO_MX7_DDRC_P_OFF]

	/* let DDR out of self-refresh */
	ldr	r7, =0x0
	str	r7, [r11, #DDRC_PWRCTL]

	/* wait until self-refresh mode entered */
4:
	ldr	r7, [r11, #DDRC_STAT]
	and	r7, r7, #0x3
	cmp	r7, #0x3
	beq	4b

	/* enable auto self-refresh */
	ldr	r7, [r11, #DDRC_PWRCTL]
	orr	r7, r7, #BIT32(0)
	str	r7, [r11, #DDRC_PWRCTL]

	.endm

	.macro wait_delay
5:
	subs	r6, r6, #0x1
	bne	5b

	.endm

	.macro ddr_enter_retention

	ldr	r11, [r0, #PM_INFO_MX7_DDRC_V_OFF]

	/* let DDR out of self-refresh */
	ldr	r7, =0x0
	str	r7, [r11, #DDRC_PCTRL_0]

	/* wait rw port_busy clear */
	ldr	r6, =BIT32(16)
	orr	r6, r6, #0x1
6:
	ldr	r7, [r11, #DDRC_PSTAT]
	ands	r7, r7, r6
	bne	6b

	ldr	r11, [r0, #PM_INFO_MX7_DDRC_V_OFF]
	/* enter self-refresh bit 5 */
	ldr	r7, =BIT32(5)
	str	r7, [r11, #DDRC_PWRCTL]

	/* wait until self-refresh mode entered */
7:
	ldr	r7, [r11, #DDRC_STAT]
	and	r7, r7, #0x3
	cmp	r7, #0x3
	bne	7b
8:
	ldr	r7, [r11, #DDRC_STAT]
	ands	r7, r7, #0x20
	beq	8b

	/* disable dram clk */
	ldr	r7, =BIT32(5)
	orr	r7, r7, #BIT32(3)
	str	r7, [r11, #DDRC_PWRCTL]

	ldr	r11, [r0, #PM_INFO_MX7_ANATOP_V_OFF]
	ldr	r7, [r11, #ANADIG_DIGPROG]
	and	r7, r7, #0xff
	cmp	r7, #0x11
	bne	10f

	/* TO 1.1 */
	ldr	r11, [r0, #PM_INFO_MX7_IOMUXC_GPR_V_OFF]
	ldr	r7, =0x38000000
	str	r7, [r11]

	/* LPSR mode need to use TO1.0 flow as IOMUX lost power */
	ldr	r10, [r0, #PM_INFO_MX7_LPSR_V_OFF]
	ldr	r7, [r10]
	cmp	r7, #0x0
	beq	11f
10:
	/* reset ddr_phy  */
	ldr	r11, [r0, #PM_INFO_MX7_ANATOP_V_OFF]
	ldr	r7, =0x0
	str	r7, [r11, #ANADIG_SNVS_MISC_CTRL]

	/* delay 7 us */
	ldr	r6, =6000
	wait_delay

	ldr	r11, [r0, #PM_INFO_MX7_SRC_V_OFF]
	ldr	r6, =0x1000
	ldr	r7, [r11, r6]
	orr	r7, r7, #0x1
	str	r7, [r11, r6]
11:
	/* turn off ddr power */
	ldr	r11, [r0, #PM_INFO_MX7_ANATOP_V_OFF]
	ldr	r7, =(0x1 << 29)
	str	r7, [r11, #ANADIG_SNVS_MISC_CTRL_SET]

	ldr	r11, [r0, #PM_INFO_MX7_SRC_V_OFF]
	ldr	r6, =0x1000
	ldr	r7, [r11, r6]
	orr	r7, r7, #0x1
	str	r7, [r11, r6]

	.endm

	.macro ddr_exit_retention

	cmp	r5, #0x0
	ldreq	r1, [r0, #PM_INFO_MX7_ANATOP_V_OFF]
	ldrne	r1, [r0, #PM_INFO_MX7_ANATOP_P_OFF]
	ldreq	r2, [r0, #PM_INFO_MX7_SRC_V_OFF]
	ldrne	r2, [r0, #PM_INFO_MX7_SRC_P_OFF]
	ldreq	r3, [r0, #PM_INFO_MX7_DDRC_V_OFF]
	ldrne	r3, [r0, #PM_INFO_MX7_DDRC_P_OFF]
	ldreq	r4, [r0, #PM_INFO_MX7_DDRC_PHY_V_OFF]
	ldrne	r4, [r0, #PM_INFO_MX7_DDRC_PHY_P_OFF]
	ldreq	r10, [r0, #PM_INFO_MX7_CCM_V_OFF]
	ldrne	r10, [r0, #PM_INFO_MX7_CCM_P_OFF]
	ldreq	r11, [r0, #PM_INFO_MX7_IOMUXC_GPR_V_OFF]
	ldrne	r11, [r0, #PM_INFO_MX7_IOMUXC_GPR_P_OFF]

	/* turn on ddr power */
	ldr	r7, =BIT32(29)
	str	r7, [r1, #ANADIG_SNVS_MISC_CTRL_CLR]

	ldr	r6, =50
	wait_delay

	/* clear ddr_phy reset */
	ldr	r6, =0x1000
	ldr	r7, [r2, r6]
	orr	r7, r7, #0x3
	str	r7, [r2, r6]
	ldr	r7, [r2, r6]
	bic	r7, r7, #0x1
	str	r7, [r2, r6]
13:
	ldr	r6, [r0, #PM_INFO_MX7_DDRC_REG_NUM_OFF]
	ldr	r7, =PM_INFO_MX7_DDRC_REG_OFF
	add	r7, r7, r0
14:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	str	r9, [r3, r8]
	subs	r6, r6, #0x1
	bne	14b
	ldr	r7, =0x20
	str	r7, [r3, #DDRC_PWRCTL]
	ldr	r7, =0x0
	str	r7, [r3, #DDRC_DFIMISC]

	/* do PHY, clear ddr_phy reset */
	ldr	r6, =0x1000
	ldr	r7, [r2, r6]
	bic	r7, r7, #0x2
	str	r7, [r2, r6]

	ldr	r7, [r1, #ANADIG_DIGPROG]
	and	r7, r7, #0xff
	cmp	r7, #0x11
	bne	12f

	/*
	 * TKT262940:
	 * System hang when press RST for DDR PAD is
	 * in retention mode, fixed on TO1.1
	 */
	ldr	r7, [r11]
	bic	r7, r7, #BIT32(27)
	str	r7, [r11]
	ldr	r7, [r11]
	bic	r7, r7, #BIT32(29)
	str	r7, [r11]
12:
	ldr	r7, =BIT32(30)
	str	r7, [r1, #ANADIG_SNVS_MISC_CTRL_SET]

	/* need to delay ~5mS */
	ldr	r6, =0x100000
	wait_delay

	ldr	r6, [r0, #PM_INFO_MX7_DDRC_PHY_REG_NUM_OFF]
	ldr	r7, =PM_INFO_MX7_DDRC_PHY_REG_OFF
	add	r7, r7, r0

15:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	str	r9, [r4, r8]
	subs	r6, r6, #0x1
	bne	15b

	ldr	r7, =0x0
	add	r9, r10, #0x4000
	str	r7, [r9, #0x130]

	ldr	r7, =0x170
	orr	r7, r7, #0x8
	str	r7, [r11, #0x20]

	ldr	r7, =0x2
	add	r9, r10, #0x4000
	str	r7, [r9, #0x130]

	ldr	r7, =0xf
	str	r7, [r4, #DDRPHY_LP_CON0]

	/* wait until self-refresh mode entered */
16:
	ldr	r7, [r3, #DDRC_STAT]
	and	r7, r7, #0x3
	cmp	r7, #0x3
	bne	16b
	ldr	r7, =0x0
	str	r7, [r3, #DDRC_SWCTL]
	ldr	r7, =0x1
	str	r7, [r3, #DDRC_DFIMISC]
	ldr	r7, =0x1
	str	r7, [r3, #DDRC_SWCTL]
17:
	ldr	r7, [r3, #DDRC_SWSTAT]
	and	r7, r7, #0x1
	cmp	r7, #0x1
	bne	17b
18:
	ldr	r7, [r3, #DDRC_STAT]
	and	r7, r7, #0x20
	cmp	r7, #0x20
	bne	18b

	/* let DDR out of self-refresh */
	ldr	r7, =0x0
	str	r7, [r3, #DDRC_PWRCTL]
19:
	ldr	r7, [r3, #DDRC_STAT]
	and	r7, r7, #0x30
	cmp	r7, #0x0
	bne	19b

20:
	ldr	r7, [r3, #DDRC_STAT]
	and	r7, r7, #0x3
	cmp	r7, #0x1
	bne	20b

	/* enable port */
	ldr	r7, =0x1
	str	r7, [r3, #DDRC_PCTRL_0]

	/* enable auto self-refresh */
	ldr	r7, [r3, #DDRC_PWRCTL]
	orr	r7, r7, #(1 << 0)
	str	r7, [r3, #DDRC_PWRCTL]

	.endm

FUNC imx7_suspend, :
UNWIND(	.cantunwind)
	push	{r4-r12}

	/* make sure SNVS clk is enabled */
	ldr	r11, [r0, #PM_INFO_MX7_CCM_V_OFF]
	add	r11, r11, #0x4000
	ldr	r7, =0x3
	str	r7, [r11, #CCM_SNVS_LPCG]

	/* check whether it is a standby mode */
	ldr	r11, [r0, #PM_INFO_MX7_GPC_V_OFF]
	ldr	r7, [r11, #GPC_PGC_C0]
	cmp	r7, #0
	beq	ddr_only_self_refresh

	/*
	 * The value of r0 is mapped the same in origin table and IRAM table,
	 * thus no need to care r0 here.
	 */
	ldr	r1, [r0, #PM_INFO_MX7_PBASE_OFF]
	ldr	r4, [r0, #PM_INFO_MX7_SIZE_OFF]

	/*
	 * counting the resume address in iram
	 * to set it in SRC register.
	 */
	ldr	r6, =imx7_suspend
	ldr	r7, =resume
	sub	r7, r7, r6
	add	r8, r1, r4
	add	r9, r8, r7

	ldr	r11, [r0, #PM_INFO_MX7_SRC_V_OFF]
	/* store physical resume addr and pm_info address. */
	str	r9, [r11, #MX7_SRC_GPR1]
	str	r1, [r11, #MX7_SRC_GPR2]

	disable_l1_dcache

	store_ttbr

	ldr	r11, [r0, #PM_INFO_MX7_GPC_V_OFF]
	ldr	r7, [r11, #GPC_PGC_FM]
	cmp	r7, #0
	beq	ddr_only_self_refresh

	ddr_enter_retention
	/* enter LPSR mode if resume addr is valid */
	ldr	r11, [r0, #PM_INFO_MX7_LPSR_V_OFF]
	ldr	r7, [r11]
	cmp	r7, #0x0
	beq	ddr_retention_enter_out

	/* disable STOP mode before entering LPSR */
	ldr	r11, [r0, #PM_INFO_MX7_GPC_V_OFF]
	ldr	r7, [r11]
	bic	r7, #0xf
	str	r7, [r11]

	/* shut down vddsoc to enter lpsr mode */
	ldr	r11, [r0, #PM_INFO_MX7_SNVS_V_OFF]
	ldr	r7, [r11, #0x38]
	orr	r7, r7, #0x60
	str	r7, [r11, #0x38]
	dsb
wait_shutdown:
	wfi
	b	wait_shutdown

ddr_only_self_refresh:
	ddrc_enter_self_refresh
	b	wfi
ddr_retention_enter_out:
	ldr	r11, [r0, #PM_INFO_MX7_GIC_DIST_V_OFF]
	ldr	r7, =0x0
	ldr	r8, =0x1000
	str	r7, [r11, r8]

	ldr	r11, [r0, #PM_INFO_MX7_GPC_V_OFF]
	ldr	r4, [r11, #MX7D_GPC_IMR1]
	ldr	r5, [r11, #MX7D_GPC_IMR2]
	ldr	r6, [r11, #MX7D_GPC_IMR3]
	ldr	r7, [r11, #MX7D_GPC_IMR4]

	ldr	r8, =0xffffffff
	str	r8, [r11, #MX7D_GPC_IMR1]
	str	r8, [r11, #MX7D_GPC_IMR2]
	str	r8, [r11, #MX7D_GPC_IMR3]
	str	r8, [r11, #MX7D_GPC_IMR4]

	/*
	 * enable the RBC bypass counter here
	 * to hold off the interrupts. RBC counter
	 * = 8 (240us). With this setting, the latency
	 * from wakeup interrupt to ARM power up
	 * is ~250uS.
	 */
	ldr	r8, [r11, #0x14]
	bic	r8, r8, #(0x3f << 24)
	orr	r8, r8, #(0x8 << 24)
	str	r8, [r11, #0x14]

	/* enable the counter. */
	ldr	r8, [r11, #0x14]
	orr	r8, r8, #(0x1 << 30)
	str	r8, [r11, #0x14]

	/* unmask all the GPC interrupts. */
	str	r4, [r11, #MX7D_GPC_IMR1]
	str	r5, [r11, #MX7D_GPC_IMR2]
	str	r6, [r11, #MX7D_GPC_IMR3]
	str	r7, [r11, #MX7D_GPC_IMR4]

	/*
	 * now delay for a short while (3usec)
	 * ARM is at 1GHz at this point
	 * so a short loop should be enough.
	 * this delay is required to ensure that
	 * the RBC counter can start counting in
	 * case an interrupt is already pending
	 * or in case an interrupt arrives just
	 * as ARM is about to assert DSM_request.
	 */
	ldr	r7, =2000
rbc_loop:
	subs	r7, r7, #0x1
	bne	rbc_loop
wfi:
	dsb
	/* Enter stop mode */
	wfi

	mov	r5, #0x0

	ldr	r11, [r0, #PM_INFO_MX7_GPC_V_OFF]
	ldr	r7, [r11, #GPC_PGC_FM]
	cmp	r7, #0
	beq	wfi_ddr_self_refresh_out

	ddr_exit_retention
	b	wfi_ddr_retention_out
wfi_ddr_self_refresh_out:
	ddrc_exit_self_refresh
wfi_ddr_retention_out:

	/* check whether it is a standby mode */
	ldr	r11, [r0, #PM_INFO_MX7_GPC_V_OFF]
	ldr	r7, [r11, #GPC_PGC_C0]
	cmp	r7, #0
	beq	standby_out

	ldr	r11, [r0, #PM_INFO_MX7_GIC_DIST_V_OFF]
	ldr	r7, =0x1
	ldr	r8, =0x1000
	str	r7, [r11, r8]

	restore_ttbr
standby_out:
	pop	{r4-r12}
	/* return to suspend finish */
	bx	lr

resume:
	write_iciallu
	write_bpiall
	dsb
	isb

	mov     r6, #(SCTLR_I | SCTLR_Z)
	write_sctlr r6
	isb

	/*
	 * After resume back, rom run in SVC mode,
	 * so we need to switch to monitor mode.
	 */
	cps	#CPSR_MODE_MON

	/* get physical resume address from pm_info. */
	ldr	lr, [r0, #PM_INFO_MX7_RESUME_ADDR_OFF]
	/* clear core0's entry and parameter */
	ldr	r11, [r0, #PM_INFO_MX7_SRC_P_OFF]
	mov	r7, #0x0
	str	r7, [r11, #MX7_SRC_GPR1]
	str	r7, [r11, #MX7_SRC_GPR2]

	mov	r5, #0x1

	ldr	r11, [r0, #PM_INFO_MX7_GPC_P_OFF]
	ldr	r7, [r11, #GPC_PGC_FM]
	cmp	r7, #0
	beq	dsm_ddr_self_refresh_out

	ddr_exit_retention
	b	dsm_ddr_retention_out
dsm_ddr_self_refresh_out:
	ddrc_exit_self_refresh
dsm_ddr_retention_out:

	bx	lr
END_FUNC imx7_suspend

FUNC ca7_cpu_resume, :
UNWIND(	.cantunwind)
	mov     r0, #0	@ ; write the cache size selection register to be
	write_csselr r0	@ ; sure we address the data cache
	isb		@ ; isb to sync the change to the cachesizeid reg

_inv_dcache_off:
	mov     r0, #0	@ ; set way number to 0
_inv_nextway:
	mov     r1, #0	@ ; set line number (=index) to 0
_inv_nextline:
	orr     r2, r0, r1	@ ; construct way/index value
	write_dcisw r2	@ ; invalidate data or unified cache line by set/way
	add     r1, r1, #1 << LINE_FIELD_OFFSET	@ ; increment the index
	cmp     r1, #1 << LINE_FIELD_OVERFLOW	@ ; overflow out of set field?
	bne     _inv_nextline
	add     r0, r0, #1 << WAY_FIELD_OFFSET	@ ; increment the way number
	cmp     r0, #0				@ ; overflow out of way field?
	bne     _inv_nextway

	dsb					@ ; synchronise
	isb

	/*
	 * No stack, scratch r0-r3
	 * TODO: Need to use specific configure, but not plat_xxx.
	 * Because plat_xx maybe changed in future, we can not rely on it.
	 * Need handle sp carefully.
	 */
	blx	plat_cpu_reset_early

	b	sm_pm_cpu_resume
END_FUNC ca7_cpu_resume
