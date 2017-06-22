/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

/*
 * ARMv7 Secure Services library
 */

/*
 * Variable(s)
 */
#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>

#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/unwind.h>

	.section .text.ssvce



/*
 * - MMU maintenaince support ---------------------------------------------
 */


/*
 * void secure_mmu_unifiedtlbinvall(void);
 */
FUNC secure_mmu_unifiedtlbinvall , :
UNWIND(	.fnstart)

	dsb	/* Ensure visibility of the update to translation table walks */
	write_tlbiallis

	DSB
	ISB

	MOV     PC, LR
UNWIND(	.fnend)
END_FUNC secure_mmu_unifiedtlbinvall

/*
 * void secure_mmu_unifiedtlbinvbymva(mva);
 *
 * Combine VA and current ASID, and invalidate matching TLB
 */
FUNC secure_mmu_unifiedtlbinvbymva , :
UNWIND(	.fnstart)

	b .	@ Wrong code to force fix/check the routine before using it
	dsb	/* Ensure visibility of the update to translation table walks */

	MRC     p15, 0, R1, c13, c0, 1		/* Read CP15 Context ID Register (CONTEXTIDR) */
	ANDS    R1, R1, #0xFF			/* Get current ASID */
	ORR     R1, R1, R0			/* Combine MVA and ASID */

	MCR     p15, 0, R1, c8, c7, 1		/* Invalidate Unified TLB entry by MVA */

	DSB
	ISB

	MOV     PC, LR
UNWIND(	.fnend)
END_FUNC secure_mmu_unifiedtlbinvbymva

/*
 * void secure_mmu_unifiedtlbinv_byasid(unsigned int asid)
 *
 * Invalidate TLB matching current ASID
 */
FUNC secure_mmu_unifiedtlbinv_byasid , :
UNWIND(	.fnstart)
	and     r0, r0, #0xff               /* Get ASID */
	dsb	/* Ensure visibility of the update to translation table walks */
	/* Invalidate unified TLB by ASID Inner Sharable */
	write_tlbiasidis r0
	dsb
	isb
	mov	pc, lr
UNWIND(	.fnend)
END_FUNC secure_mmu_unifiedtlbinv_byasid


