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
 * void secure_mmu_unifiedtlbinv_curasid(void)
 *
 * Invalidate TLB matching current ASID
 */
FUNC secure_mmu_unifiedtlbinv_curasid , :
UNWIND(	.fnstart)
	read_contextidr r0
	and     r0, r0, #0xff               /* Get current ASID */
	/* Invalidate unified TLB by ASID Inner Sharable */
	write_tlbiasidis r0
	dsb
	isb
	mov	pc, lr
UNWIND(	.fnend)
END_FUNC secure_mmu_unifiedtlbinv_curasid

/*
 * void secure_mmu_unifiedtlbinv_byasid(unsigned int asid)
 *
 * Invalidate TLB matching current ASID
 */
FUNC secure_mmu_unifiedtlbinv_byasid , :
UNWIND(	.fnstart)
	and     r0, r0, #0xff               /* Get ASID */
	/* Invalidate unified TLB by ASID Inner Sharable */
	write_tlbiasidis r0
	dsb
	isb
	mov	pc, lr
UNWIND(	.fnend)
END_FUNC secure_mmu_unifiedtlbinv_byasid

/*
 * void arm_cl1_d_cleanbysetway(void)
 */
FUNC arm_cl1_d_cleanbysetway , :
UNWIND(	.fnstart)

	MOV     R0, #0                  @ ; write the Cache Size selection register to be
	MCR     p15, 2, R0, c0, c0, 0   @ ; sure we address the data cache
	ISB                             @ ; ISB to sync the change to the CacheSizeID reg

	MOV     R0, #0                  @ ; set way number to 0
_cl_nextWay:
	MOV     R1, #0                  @ ; set line number (=index) to 0
_cl_nextLine:
	ORR     R2, R0, R1                          @ ; construct way/index value
	MCR     p15, 0, R2, c7, c10, 2              @ ; DCCSW Clean data or unified cache line by set/way
	ADD     R1, R1, #1 << LINE_FIELD_OFFSET     @ ; increment the index
	CMP     R1, #1 << LINE_FIELD_OVERFLOW       @ ; look for overflow out of set field
	BNE     _cl_nextLine
	ADD     R0, R0, #1 << WAY_FIELD_OFFSET      @ ; increment the way number
	CMP     R0, #0                              @ ; look for overflow out of way field
	BNE     _cl_nextWay

	DSB                             @ ; synchronise
	MOV PC, LR
UNWIND(	.fnend)
END_FUNC arm_cl1_d_cleanbysetway

FUNC arm_cl1_d_invbysetway , :
UNWIND(	.fnstart)

	MOV     R0, #0                  @ ; write the Cache Size selection register to be
	MCR     p15, 2, R0, c0, c0, 0   @ ; sure we address the data cache
	ISB                             @ ; ISB to sync the change to the CacheSizeID reg

_inv_dcache_off:    
	MOV     R0, #0                  @ ; set way number to 0
_inv_nextWay:
	MOV     R1, #0                  @ ; set line number (=index) to 0
_inv_nextLine:
	ORR     R2, R0, R1                          @ ; construct way/index value
	MCR     p15, 0, R2, c7, c6, 2               @ ; DCISW Invalidate data or unified cache line by set/way
	ADD     R1, R1, #1 << LINE_FIELD_OFFSET     @ ; increment the index
	CMP     R1, #1 << LINE_FIELD_OVERFLOW       @ ; look for overflow out of set field
	BNE     _inv_nextLine
	ADD     R0, R0, #1 << WAY_FIELD_OFFSET      @ ; increment the way number
	CMP     R0, #0                              @ ; look for overflow out of way field
	BNE     _inv_nextWay

	DSB                             @ ; synchronise
	MOV      PC, LR
UNWIND(	.fnend)
END_FUNC arm_cl1_d_invbysetway

FUNC arm_cl1_d_cleaninvbysetway , :
UNWIND(	.fnstart)

	MOV     R0, #0                  @ ; write the Cache Size selection register to be
	MCR     p15, 2, R0, c0, c0, 0   @ ; sure we address the data cache
	ISB                             @ ; ISB to sync the change to the CacheSizeID reg

	MOV     R0, #0                  @ ; set way number to 0
_cli_nextWay:
	MOV     R1, #0                  @ ; set line number (=index) to 0
_cli_nextLine:
	ORR     R2, R0, R1                          @ ; construct way/index value
	MCR     p15, 0, R2, c7, c14, 2              @ ; DCCISW Clean and Invalidate data or unified cache line by set/way
	ADD     R1, R1, #1 << LINE_FIELD_OFFSET     @ ; increment the index
	CMP     R1, #1 << LINE_FIELD_OVERFLOW       @ ; look for overflow out of set field
	BNE     _cli_nextLine
	ADD     R0, R0, #1 << WAY_FIELD_OFFSET      @ ; increment the way number
	CMP     R0, #0                              @ ; look for overflow out of way field
	BNE     _cli_nextWay

	DSB                             @ ; synchronise
	MOV PC, LR
UNWIND(	.fnend)
END_FUNC arm_cl1_d_cleaninvbysetway

/*
 * void arm_cl1_d_cleanbyva(void *s, void *e);
 */
FUNC arm_cl1_d_cleanbyva , :
UNWIND(	.fnstart)

	CMP     R0, R1                  @ ; check that end >= start. Otherwise return.
	BHI     _cl_area_exit

	MOV     R2, #0                  @ ; write the Cache Size selection register to be
	MCR     p15, 2, R2, c0, c0, 0   @ ; sure we address the data cache
	ISB                             @ ; ISB to sync the change to the CacheSizeID reg

	BIC     R0, R0, #0x1F           @ ; Mask 5 LSBits
_cl_area_nextLine:
	MCR     p15, 0, R0, c7, c10, 1              @ ; Clean data or unified cache line by MVA to PoC
	ADD     R0, R0, #1 << LINE_FIELD_OFFSET     @ ; Next cache line
	CMP     R1, R0
	BPL     _cl_area_nextLine

_cl_area_exit:
	
	DSB                             @ ; synchronise
	MOV PC, LR
UNWIND(	.fnend)
END_FUNC arm_cl1_d_cleanbyva

/*
 * void arm_cl1_d_invbyva(void *s, void *e);
 */
FUNC arm_cl1_d_invbyva , :
UNWIND(	.fnstart)

	CMP     R0, R1                      @ ; check that end >= start. Otherwise return.
	BHI     _inv_area_dcache_exit
	
	MOV     R2, #0                      @ ; write the Cache Size selection register to be
	MCR     p15, 2, R2, c0, c0, 0       @ ; sure we address the data cache
	ISB                                 @ ; ISB to sync the change to the CacheSizeID reg

_inv_area_dcache_off:
	BIC     R0, R0, #0x1F                       @ ; Mask 5 LSBits
_inv_area_dcache_nl:
	MCR     p15, 0, R0, c7, c6, 1               @ ; Invalidate data or unified cache line by MVA to PoC
	ADD     R0, R0, #1 << LINE_FIELD_OFFSET     @ ; Next cache line
	CMP     R1, R0
	BPL     _inv_area_dcache_nl

_inv_area_dcache_exit:
	DSB
	MOV PC, LR
UNWIND(	.fnend)
END_FUNC arm_cl1_d_invbyva

/*
 * void arm_cl1_d_cleaninvbyva(void *s, void *e);
 */
FUNC arm_cl1_d_cleaninvbyva , :
UNWIND(	.fnstart)

	CMP     R0, R1                  @ ; check that end >= start. Otherwise return.
	BHI     _cli_area_exit

	MOV     R2, #0                  @ ; write the Cache Size selection register to be
	MCR     p15, 2, R2, c0, c0, 0   @ ; sure we address the data cache
	ISB                             @ ; ISB to sync the change to the CacheSizeID reg

	BIC     R0, R0, #0x1F           @ ; Mask 5 LSBits
_cli_area_nextLine:
	MCR     p15, 0, R0, c7, c14, 1              @ ; Clean and Invalidate data or unified cache line by MVA to PoC
	ADD     R0, R0, #1 << LINE_FIELD_OFFSET     @ ; Next cache line
	CMP     R1, R0
	BPL     _cli_area_nextLine

_cli_area_exit:
	DSB                             @ ; synchronise
	MOV PC, LR
UNWIND(	.fnend)
END_FUNC arm_cl1_d_cleaninvbyva

/*
 * void arm_cl1_i_inv_all( void );
 *
 * Invalidates the whole instruction cache.
 * It also invalidates the BTAC.
 */
FUNC arm_cl1_i_inv_all , :
UNWIND(	.fnstart)

    /* Invalidate Entire Instruction Cache */
    write_icialluis
    DSB

    /* Flush entire branch target cache */
    write_bpiallis

    DSB                             /* ensure that maintenance operations are seen */
    ISB                             /* by the instructions rigth after the ISB */

    BX      LR
UNWIND(	.fnend)
END_FUNC arm_cl1_i_inv_all

/*
 * void arm_cl1_i_inv(void *start, void *end);
 *
 * Invalidates instruction cache area whose limits are given in parameters.
 * It also invalidates the BTAC.
 */
FUNC arm_cl1_i_inv , :
UNWIND(	.fnstart)

    CMP     R0, R1                              /* Check that end >= start. Otherwise return. */
    BHI     _inv_icache_exit

    BIC     R0, R0, #0x1F                       /* Mask 5 LSBits */
_inv_icache_nextLine:
    MCR     p15, 0, R0, c7, c5, 1               /* Invalidate ICache single entry (MVA) */
    ADD     R0, R0, #1 << LINE_FIELD_OFFSET     /* Next cache line */
    CMP     R1, R0
    BPL     _inv_icache_nextLine
    DSB

    /* Flush entire branch target cache */
    MOV     R1, #0
    MCR     p15, 0, R1, c7, c5, 6   /* write to Cache operations register */
    DSB                             /* ensure that maintenance operations are seen */
    ISB                             /* by the instructions rigth after the ISB */

_inv_icache_exit:
    BX      LR
UNWIND(	.fnend)
END_FUNC arm_cl1_i_inv
