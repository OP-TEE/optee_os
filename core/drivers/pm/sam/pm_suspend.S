/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/*
 * This file was imported from Linux arch/arm/mach-at91/pm_suspend.S and
 * relicensed with dual GPL-2.0/BSD-2-Clause with Microchip agreement.
 *
 * Copyright (c) 2021, Microchip
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <at91_pmc.h>
#include <drivers/sam/at91_ddr.h>
#include <generated/pm-defines.h>

#include "at91_pm.h"

#define	SRAMC_SELF_FRESH_ACTIVE		0x01
#define	SRAMC_SELF_FRESH_EXIT		0x00

pmc	.req	r0
tmp1	.req	r4
tmp2	.req	r5
tmp3	.req	r6

/*
 * Wait until master clock is ready (after switching master clock source)
 * @r_mckid:	register holding master clock identifier
 *
 * Side effects: overwrites tmp1
 */
.macro wait_mckrdy r_mckid
#ifdef CFG_SAMA7G5
	cmp	\r_mckid, #0
	beq	1f
2:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MCKXRDY
	beq	2b
	b	3f
#endif
1:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MCKRDY
	beq	1b
3:
.endm

/*
 * Wait until master oscillator has stabilized.
 */
.macro wait_moscrdy
1:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MOSCS
	beq	1b
.endm

/*
 * Wait for main oscillator selection is done
 */
.macro wait_moscsels
1:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MOSCSELS
	beq	1b
.endm

/*
 * Put the processor to enter the idle state
 */
.macro at91_cpu_idle

	mov	tmp1, #AT91_PMC_PCK
	str	tmp1, [pmc, #AT91_PMC_SCDR]

	dsb

	wfi		@ Wait For Interrupt

.endm

.section .text.psci.suspend

.arm


#define SUSPEND_FUNC(__name) \
__name:

#define SUSPEND_END_FUNC(__name) \
	.size __name, .-__name

.macro check_fit_in_sram since
	.if (. - \since) > 0x10000
		.error "Suspend assembly code exceeds dedicated SRAM size"
	.endif
.endm

/*
 * void at91_suspend_sram_fn(struct at91_pm_data*)
 * @input param:
 * 	@r0: base address of struct at91_pm_data
 */
.align 3
.global at91_pm_suspend_in_sram
SUSPEND_FUNC(at91_pm_suspend_in_sram)
	/* Save registers on stack */
	stmfd	sp!, {r4 - r12, lr}

	/* Drain write buffer */
	mov	tmp1, #0
	mcr	p15, 0, tmp1, c7, c10, 4

	ldr	tmp1, [r0, #PM_DATA_PMC]
	str	tmp1, .pmc_base
	ldr	tmp1, [r0, #PM_DATA_RAMC0]
	str	tmp1, .sramc_base
	ldr	tmp1, [r0, #PM_DATA_MODE]
	str	tmp1, .pm_mode
	/* Both ldrne below are here to preload their address in the TLB */
	ldr	tmp1, [r0, #PM_DATA_SHDWC]
	str	tmp1, .shdwc
	cmp	tmp1, #0
	ldrne	tmp2, [tmp1, #0]
	ldr	tmp1, [r0, #PM_DATA_SFRBU]
	str	tmp1, .sfrbu
	cmp	tmp1, #0
	ldrne	tmp2, [tmp1, #0x10]

	/* Active the self-refresh mode */
	mov	r0, #SRAMC_SELF_FRESH_ACTIVE
	bl	at91_sramc_self_refresh

	ldr	r0, .pm_mode
	cmp	r0, #AT91_PM_STANDBY
	beq	standby
	cmp	r0, #AT91_PM_BACKUP
	beq	backup_mode

	bl	at91_ulp_mode
	b	exit_suspend

standby:
	/* Wait for interrupt */
	ldr	pmc, .pmc_base
	at91_cpu_idle
	b	exit_suspend

backup_mode:
	bl	at91_backup_mode
	b	exit_suspend

exit_suspend:
	/* Exit the self-refresh mode */
	mov	r0, #SRAMC_SELF_FRESH_EXIT
	bl	at91_sramc_self_refresh

	/* Restore registers, and return */
	ldmfd	sp!, {r4 - r12, pc}
SUSPEND_END_FUNC(at91_pm_suspend_in_sram)

SUSPEND_FUNC(at91_backup_mode)
	/* Switch the master clock source to slow clock. */
	ldr	pmc, .pmc_base
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	bic	tmp1, tmp1, #AT91_PMC_CSS
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	mov	tmp3, #0
	wait_mckrdy tmp3

	/*BUMEN*/
	ldr	r0, .sfrbu
	mov	tmp1, #0x1
	str	tmp1, [r0, #0x10]

	/* Shutdown */
	ldr	r0, .shdwc
	mov	tmp1, #0xA5000000
	add	tmp1, tmp1, #0x1
	str	tmp1, [r0, #0]
SUSPEND_END_FUNC(at91_backup_mode)

.macro at91_pm_ulp0_mode
	ldr	pmc, .pmc_base
	ldr	tmp2, .pm_mode

	/* Check if ULP0 fast variant has been requested. */
	cmp	tmp2, #AT91_PM_ULP0_FAST
	bne	0f

	/* Set highest prescaler for power saving */
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	bic	tmp1, tmp1, #AT91_PMC_PRES
	orr	tmp1, tmp1, #AT91_PMC_PRES_64
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	mov	tmp3, #0
	wait_mckrdy tmp3
	b	1f

0:
	/* Turn off the crystal oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	bic	tmp1, tmp1, #AT91_PMC_MOSCEN
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Save RC oscillator state */
	ldr	tmp1, [pmc, #AT91_PMC_SR]
	str	tmp1, .saved_osc_status
	tst	tmp1, #AT91_PMC_MOSCRCS
	bne	1f

	/* Turn off RC oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	bic	tmp1, tmp1, #AT91_PMC_MOSCRCEN
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Wait main RC disabled done */
2:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MOSCRCS
	bne	2b

	/* Wait for interrupt */
1:	at91_cpu_idle

	/* Check if ULP0 fast variant has been requested. */
	cmp	tmp2, #AT91_PM_ULP0_FAST
	bne	5f

	/* Set lowest prescaler for fast resume. */
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	bic	tmp1, tmp1, #AT91_PMC_PRES
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	mov	tmp3, #0
	wait_mckrdy tmp3
	b	6f

5:	/* Restore RC oscillator state */
	ldr	tmp1, .saved_osc_status
	tst	tmp1, #AT91_PMC_MOSCRCS
	beq	4f

	/* Turn on RC oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	orr	tmp1, tmp1, #AT91_PMC_MOSCRCEN
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Wait main RC stabilization */
3:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MOSCRCS
	beq	3b

	/* Turn on the crystal oscillator */
4:	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	orr	tmp1, tmp1, #AT91_PMC_MOSCEN
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	wait_moscrdy
6:
.endm

/**
 * Note: This procedure only applies on the platform which uses
 * the external crystal oscillator as a main clock source.
 */
.macro at91_pm_ulp1_mode
	ldr	pmc, .pmc_base

	/* Save RC oscillator state and check if it is enabled. */
	ldr	tmp1, [pmc, #AT91_PMC_SR]
	str	tmp1, .saved_osc_status
	tst	tmp1, #AT91_PMC_MOSCRCS
	bne	2f

	/* Enable RC oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	orr	tmp1, tmp1, #AT91_PMC_MOSCRCEN
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Wait main RC stabilization */
1:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MOSCRCS
	beq	1b

	/* Switch the main clock source to 12-MHz RC oscillator */
2:	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	bic	tmp1, tmp1, #AT91_PMC_MOSCSEL
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	wait_moscsels

	/* Disable the crystal oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	bic	tmp1, tmp1, #AT91_PMC_MOSCEN
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Switch the master clock source to main clock */
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	bic	tmp1, tmp1, #AT91_PMC_CSS
	orr	tmp1, tmp1, #AT91_PMC_CSS_MAIN
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	mov	tmp3, #0
	wait_mckrdy tmp3

	/* Enter the ULP1 mode by set WAITMODE bit in CKGR_MOR */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	orr	tmp1, tmp1, #AT91_PMC_WAITMODE
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Quirk for SAM9X60's PMC */
	nop
	nop

	wait_mckrdy tmp3

	/* Enable the crystal oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	orr	tmp1, tmp1, #AT91_PMC_MOSCEN
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	wait_moscrdy

	/* Switch the master clock source to slow clock */
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	bic	tmp1, tmp1, #AT91_PMC_CSS
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	wait_mckrdy tmp3

	/* Switch main clock source to crystal oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	orr	tmp1, tmp1, #AT91_PMC_MOSCSEL
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	wait_moscsels

	/* Switch the master clock source to main clock */
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	bic	tmp1, tmp1, #AT91_PMC_CSS
	orr	tmp1, tmp1, #AT91_PMC_CSS_MAIN
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	wait_mckrdy tmp3

	/* Restore RC oscillator state */
	ldr	tmp1, .saved_osc_status
	tst	tmp1, #AT91_PMC_MOSCRCS
	bne	3f

	/* Disable RC oscillator */
	ldr	tmp1, [pmc, #AT91_CKGR_MOR]
	bic	tmp1, tmp1, #AT91_PMC_MOSCRCEN
	bic	tmp1, tmp1, #AT91_PMC_KEY_MASK
	orr	tmp1, tmp1, #AT91_PMC_KEY
	str	tmp1, [pmc, #AT91_CKGR_MOR]

	/* Wait RC oscillator disable done */
4:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_MOSCRCS
	bne	4b

3:
.endm

/*
 * Save PLLA setting and disable it
 *
 * Side effects: overwrites tmp1, tmp2
 */
.macro at91_plla_disable
#ifdef CFG_SAMA7G5
	/* Save PLLA settings */
	ldr	tmp2, [pmc, #AT91_PMC_PLL_UPDT]
	bic	tmp2, tmp2, #AT91_PMC_PLL_UPDT_ID
	str	tmp2, [pmc, #AT91_PMC_PLL_UPDT]

	/* save div */
	mov	tmp1, #0
	ldr	tmp2, [pmc, #AT91_PMC_PLL_CTRL0]
	bic	tmp2, tmp2, #0xffffff00
	orr	tmp1, tmp1, tmp2

	/* save mul */
	ldr	tmp2, [pmc, #AT91_PMC_PLL_CTRL1]
	bic	tmp2, tmp2, #0xffffff
	orr	tmp1, tmp1, tmp2
	str	tmp1, .saved_pllar

	/* step 2 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_UPDATE
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_ID
	str	tmp1, [pmc, #AT91_PMC_PLL_UPDT]

	/* step 3 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_CTRL0]
	bic	tmp1, tmp1, #AT91_PMC_PLL_CTRL0_ENPLLCK
	orr	tmp1, tmp1, #AT91_PMC_PLL_CTRL0_ENPLL
	str	tmp1, [pmc, #AT91_PMC_PLL_CTRL0]

	/* step 4 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
	orr	tmp1, tmp1, #AT91_PMC_PLL_UPDT_UPDATE
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_ID
	str	tmp1, [pmc, #AT91_PMC_PLL_UPDT]

	/* step 5 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_CTRL0]
	bic	tmp1, tmp1, #AT91_PMC_PLL_CTRL0_ENPLL
	str	tmp1, [pmc, #AT91_PMC_PLL_CTRL0]

	/* step 6 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
	orr	tmp1, tmp1, #AT91_PMC_PLL_UPDT_UPDATE
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_ID
	str	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
#else
	/* Save PLLA setting and disable it */
	ldr	tmp1, [pmc, #AT91_CKGR_PLLAR]
	str	tmp1, .saved_pllar

	/* Disable PLLA. */
	mov	tmp1, #AT91_PMC_PLLCOUNT
	orr	tmp1, tmp1, #(1 << 29)		/* bit 29 always set */
	str	tmp1, [pmc, #AT91_CKGR_PLLAR]
#endif
2:
.endm

/*
 * Enable PLLA with the saved setting
 *
 * Side effects: overwrites tmp1, tmp2
 */
.macro at91_plla_enable
#ifdef CFG_SAMA7G5
	/* step 1 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_ID
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_UPDATE
	str	tmp1, [pmc, #AT91_PMC_PLL_UPDT]

	/* step 2 */
	ldr	tmp1, =AT91_PMC_PLL_ACR_DEFAULT_PLLA
	str	tmp1, [pmc, #AT91_PMC_PLL_ACR]

	/* step 3 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_CTRL1]
	ldr	tmp2, .saved_pllar
	bic	tmp2, tmp2, #0xffffff
	orr	tmp1, tmp1, tmp2
	str	tmp1, [pmc, #AT91_PMC_PLL_CTRL1]

	/* step 4 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_ID
	orr	tmp1, tmp1, #AT91_PMC_PLL_UPDT_UPDATE
	str	tmp1, [pmc, #AT91_PMC_PLL_UPDT]

	/* step 5 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_CTRL0]
	orr	tmp1, tmp1, #AT91_PMC_PLL_CTRL0_ENLOCK
	orr	tmp1, tmp1, #AT91_PMC_PLL_CTRL0_ENPLL
	orr	tmp1, tmp1, #AT91_PMC_PLL_CTRL0_ENPLLCK
	bic	tmp1, tmp1, #0xff
	ldr	tmp2, .saved_pllar
	bic	tmp2, tmp2, #0xffffff00
	orr	tmp1, tmp1, tmp2
	str	tmp1, [pmc, #AT91_PMC_PLL_CTRL0]

	/* step 6 */
	ldr	tmp1, [pmc, #AT91_PMC_PLL_UPDT]
	orr	tmp1, tmp1, #AT91_PMC_PLL_UPDT_UPDATE
	bic	tmp1, tmp1, #AT91_PMC_PLL_UPDT_ID
	str	tmp1, [pmc, #AT91_PMC_PLL_UPDT]

	/* step 7 */
3:	ldr	tmp1, [pmc, #AT91_PMC_PLL_ISR0]
	tst	tmp1, #0x1
	beq	3b
#else
	ldr	tmp2, .saved_pllar

	/* Restore PLLA setting */
	str	tmp2, [pmc, #AT91_CKGR_PLLAR]

	/* Enable PLLA. */
	tst	tmp2, #(AT91_PMC_MUL &  0xff0000)
	bne	1f
	tst	tmp2, #(AT91_PMC_MUL & ~0xff0000)
	beq	2f

1:	ldr	tmp1, [pmc, #AT91_PMC_SR]
	tst	tmp1, #AT91_PMC_LOCKA
	beq	1b
2:
#endif
.endm

#ifdef CFG_SAMA7G5
/*
 * at91_mckx_ps_enable:	save MCK1..4 settings and switch it to main clock
 *
 * Side effects: overwrites tmp1, tmp2, tmp3
 */
.macro at91_mckx_ps_enable
	ldr	pmc, .pmc_base

	/* There are 4 MCKs we need to handle: MCK1..4 */
	mov	tmp1, #1
e_loop:
	/* Write MCK ID to retrieve the settings */
	str	tmp1, [pmc, #AT91_PMC_MCR_V2]
	ldr	tmp2, [pmc, #AT91_PMC_MCR_V2]

	cmp	tmp1, #1
	streq	tmp2, .saved_mck1
	cmp	tmp1, #2
	streq	tmp2, .saved_mck2
	cmp	tmp1, #3
	streq	tmp2, .saved_mck3
	cmp	tmp1, #4
	streq	tmp2, .saved_mck4

	/* Use CSS=MD_SLOW_CLK and DIV=64. */
	bic	tmp2, tmp2, #AT91_PMC_MCR_V2_CSS_MASK
	bic	tmp2, tmp2, #AT91_PMC_MCR_V2_DIV_MASK
	orr	tmp2, tmp2, #AT91_PMC_MCR_V2_CSS_MD_SLCK
	orr	tmp2, tmp2, #AT91_PMC_MCR_V2_DIV64
	orr	tmp2, tmp2, #AT91_PMC_MCR_V2_CMD
	str	tmp2, [pmc, #AT91_PMC_MCR_V2]

	mov	tmp2, tmp1
	wait_mckrdy tmp1
	mov	tmp1, tmp2

	add	tmp1, tmp1, #1
	cmp	tmp1, #5
	bne	e_loop
.endm

/*
 * at91_mckx_ps_restore: restore MCK1..4 settings
 *
 * Side effects: overwrites tmp1, tmp2, tmp3
 */
.macro at91_mckx_ps_restore
	ldr	pmc, .pmc_base

	/* There are 4 MCKs we need to handle: MCK1..4 */
	mov	tmp1, #1
	ldr	tmp2, .saved_mck1
r_loop:
	cmp	tmp1, #2
	ldreq	tmp2, .saved_mck2
	cmp	tmp1, #3
	ldreq	tmp2, .saved_mck3
	cmp	tmp1, #4
	ldreq	tmp2, .saved_mck4

	/* Write MCK ID to retrieve the settings */
	str	tmp1, [pmc, #AT91_PMC_MCR_V2]
	ldr	tmp3, [pmc, #AT91_PMC_MCR_V2]

	/* We need to restore CSS and DIV. */
	bic	tmp3, tmp3, #AT91_PMC_MCR_V2_CSS_MASK
	bic	tmp3, tmp3, #AT91_PMC_MCR_V2_DIV_MASK
	orr	tmp3, tmp3, tmp2
	bic	tmp3, tmp3, #AT91_PMC_MCR_V2_ID_MASK
	orr	tmp3, tmp3, tmp1
	orr	tmp3, tmp3, #AT91_PMC_MCR_V2_CMD
	str	tmp3, [pmc, #AT91_PMC_MCR_V2]

	mov	tmp2, tmp1
	wait_mckrdy tmp1
	mov	tmp1, tmp2

	add	tmp1, tmp1, #1
	cmp	tmp1, #5
	bne	r_loop
.endm
#endif

SUSPEND_FUNC(at91_ulp_mode)
#ifdef CFG_SAMA7G5
	at91_mckx_ps_enable
#endif

	ldr	pmc, .pmc_base
	ldr	tmp3, .pm_mode

	/* Save Master clock setting */
	ldr	tmp1, [pmc, #AT91_PMC_MCKR]
	str	tmp1, .saved_mckr

	/*
	 * Set master clock source to:
	 * - MAINCK if using ULP0 fast variant
	 * - slow clock, otherwise
	 */
	bic	tmp1, tmp1, #AT91_PMC_CSS
	cmp	tmp3, #AT91_PM_ULP0_FAST
	bne	save_mck
	orr	tmp1, tmp1, #AT91_PMC_CSS_MAIN
save_mck:
	str	tmp1, [pmc, #AT91_PMC_MCKR]

	mov	tmp3, #0
	wait_mckrdy tmp3

	at91_plla_disable

	ldr	tmp3, .pm_mode
	cmp	tmp3, #AT91_PM_ULP1
	beq	ulp1_mode

	at91_pm_ulp0_mode
	b	ulp_exit

ulp1_mode:
	at91_pm_ulp1_mode
	b	ulp_exit

ulp_exit:
	ldr	pmc, .pmc_base

	at91_plla_enable

	/*
	 * Restore master clock setting
	 */
	ldr	tmp2, .saved_mckr
	str	tmp2, [pmc, #AT91_PMC_MCKR]

	mov	tmp3, #0
	wait_mckrdy tmp3

#ifdef CFG_SAMA7G5
	at91_mckx_ps_restore
#endif

	mov	pc, lr
SUSPEND_END_FUNC(at91_ulp_mode)

/*
 * void at91_sramc_self_refresh(unsigned int is_active)
 *
 * @input param:
 *	@r0: 1 - active self-refresh mode
 *	     0 - exit self-refresh mode
 * register usage:
 *	@r2: base address of the sram controller
 */

SUSPEND_FUNC(at91_sramc_self_refresh)
	ldr	r2, .sramc_base

	/*
	 * DDR Memory controller
	 */
	tst	r0, #SRAMC_SELF_FRESH_ACTIVE
	beq	ddrc_exit_sf

	/* LPDDR1 --> force DDR2 mode during self-refresh */
	ldr	r3, [r2, #AT91_DDRSDRC_MDR]
	str	r3, .saved_sam9_mdr
	bic	r3, r3, #~AT91_DDRSDRC_MD
	cmp	r3, #AT91_DDRSDRC_MD_LOW_POWER_DDR
	ldreq	r3, [r2, #AT91_DDRSDRC_MDR]
	biceq	r3, r3, #AT91_DDRSDRC_MD
	orreq	r3, r3, #AT91_DDRSDRC_MD_DDR2
	streq	r3, [r2, #AT91_DDRSDRC_MDR]

	/* Active DDRC self-refresh mode */
	ldr	r3, [r2, #AT91_DDRSDRC_LPR]
	str	r3, .saved_sam9_lpr
	bic	r3, r3, #AT91_DDRSDRC_LPCB
	orr	r3, r3, #AT91_DDRSDRC_LPCB_SELF_REFRESH
	str	r3, [r2, #AT91_DDRSDRC_LPR]

	b	exit_sramc_sf

ddrc_exit_sf:
	/* Restore MDR in case of LPDDR1 */
	ldr	r3, .saved_sam9_mdr
	str	r3, [r2, #AT91_DDRSDRC_MDR]
	/* Restore LPR on AT91 with DDRAM */
	ldr	r3, .saved_sam9_lpr
	str	r3, [r2, #AT91_DDRSDRC_LPR]

exit_sramc_sf:
	mov	pc, lr
SUSPEND_END_FUNC(at91_sramc_self_refresh)

.pmc_base:
	.word 0
.sramc_base:
	.word 0
.shdwc:
	.word 0
.sfrbu:
	.word 0
.pm_mode:
	.word 0
.saved_mckr:
	.word 0
.saved_pllar:
	.word 0
.saved_sam9_lpr:
	.word 0
.saved_sam9_mdr:
	.word 0
.saved_osc_status:
	.word 0
#ifdef CFG_SAMA7G5
.saved_mck1:
	.word 0
.saved_mck2:
	.word 0
.saved_mck3:
	.word 0
.saved_mck4:
	.word 0
#endif

.global at91_pm_suspend_in_sram_sz
at91_pm_suspend_in_sram_sz:
	.word .-at91_pm_suspend_in_sram

check_fit_in_sram at91_pm_suspend_in_sram
