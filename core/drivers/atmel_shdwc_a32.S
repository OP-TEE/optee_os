/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015 Atmel Corporation,
 *                    Nicolas Ferre <nicolas.ferre@atmel.com>
 * Copyright (c) 2021, Microchip
 */


#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <drivers/atmel_shdwc.h>
#include <drivers/sam/at91_ddr.h>

#include "at91_pmc.h"

/*
 * Code size of shutdown assembly must fit in a single Cortex-A5 cache
 * line which is 8 words long (32 bytes) since SDRAM might be disabled and thus
 * not accessible to fetch code or data from it.
 */
.macro check_fit_in_cacheline since
	.if (. - \since) > 32
		.error "Shutdown assembly code exceeds cache line size"
	.endif
.endm

/**
 * Shutdown the CPU
 *
 * This function is in assembly to be sure the code fits in a single cache line.
 * We are going to power down the SDRAM and thus we can't fetch code from it
 * once powered down.
 *
 * r0 = mpddrc_base
 * r1 = shdwc_base
 * r2 = pmc_base
 */
FUNC __atmel_shdwc_shutdown , :

	mov_imm r3, AT91_DDRSDRC_LPDDR2_PWOFF
	mov_imm r4, (AT91_SHDW_KEY | AT91_SHDW_SHDW)

	/*
	 * Read values from both shutdown controller and PMC to ensure the
	 * translations will be in the TLB.
	 */
	ldr	r6, [r1, #AT91_SHDW_CR]
	ldr	r6, [r2, #AT91_PMC_MCKR]

	/* Power down SDRAM0 if mpddrc_base is set */
	tst	r0, #0
	beq	1f

/* Align to cache line to ensure the rest of code fits in a single line */
.balign 32
__atmel_shdwc_shutdown_sdram_disabled:
	str	r3, [r0, #AT91_DDRSDRC_LPR]

	/* Switch the master clock source to slow clock. */
1:
	ldr	r6, [r2, #AT91_PMC_MCKR]
	bic	r6, r6, #AT91_PMC_CSS
	str	r6, [r2, #AT91_PMC_MCKR]

	/* Wait for clock switch. */
2:
	ldr	r6, [r2, #AT91_PMC_SR]
	tst	r6, #AT91_PMC_MCKRDY
	beq	2b

	/* Shutdown CPU */
	str	r4, [r1, #AT91_SHDW_CR]

	check_fit_in_cacheline __atmel_shdwc_shutdown_sdram_disabled

	/* We should never reach this since we shut down the CPU */
	b	.
END_FUNC __atmel_shdwc_shutdown
