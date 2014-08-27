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

#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>

/* tee inits/monitors services */
.global ssvce_monitormutex
.global secure_get_cpu_id
.global secure_setstacks
.global secure_restorecontext
.global secure_savecontext
.global secure_savecontext_reenter
.global ssvce_topoftempstack

/* mmu init */
.global secure_mmu_init
.global secure_mmu_init_cpuN
.global secure_mmu_disable /* TODO: align with cpu_mmu_enable() */

/* TLB maintenance */
.global secure_mmu_datatlbinvall
.global secure_mmu_unifiedtlbinvall
.global secure_mmu_unifiedtlbinvbymva
.global secure_mmu_unifiedtlbinv_curasid
.global secure_mmu_unifiedtlbinv_byasid

/* cache maintenance */
.global arm_cl1_d_cleanbysetway
.global arm_cl1_d_invbysetway
.global arm_cl1_d_cleaninvbysetway
.global arm_cl1_d_cleanbypa
.global arm_cl1_d_invbypa
.global arm_cl1_d_cleaninvbypa
.global arm_cl1_i_inv_all
.global arm_cl1_i_inv

/*
 * Get CPU id: macro for local call.
 * export unsigned long secure_get_cpu_id(void).
 */
.macro GET_CPU_ID reg
    MRC p15, 0, \reg, c0, c0, 5     @ ; read MPIDR
    AND \reg, #0x3                  @ ; Get CPU ID
.endm

.code 32
.section .text
.balign 4

secure_get_cpu_id:
	GET_CPU_ID R0
	MOV PC, LR


/*
 * Store TTBR0 base address for tee core and TAs.
 * These are defined from scatter file and resolved during linkage.
 * Currently all cores use the same MMU L1 tables (core and TAs).
 * Maybe some day, each CPU will use its own MMU table.
 */
CORE0_TTBR0_ADDR:
    .word SEC_MMU_TTB_FLD
CORE0_TA_TTBR0_ADDR:
    .word SEC_TA_MMU_TTB_FLD

/*
 * secure_mmu_init - init MMU for primary cpu
 */
secure_mmu_init:
  MRC     p15, 0, r0, c1, c0, 0   @  store in r0 contain of SCTLR (system control register) from CP15 
  BIC     r0, r0, #0x00004        @  disable data cache. (BIC = bit clear)
  BIC     r0, r0, #0x01000        @  disable instruction cache.
  MCR     p15, 0, r0, c1, c0, 0

  MOV     r0, #0x05               @ domain 0: teecore, domain 1: TA
  MCR     p15, 0, r0, c3, c0, 0

  /* load tee core default mapping */
  push    {lr}
  LDR     r0, CORE0_TTBR0_ADDR
  LDR     r1, CORE0_TA_TTBR0_ADDR
  BL      core_init_mmu
  pop     {lr}

/*  
 * Set Table Table Base Control Reg
 * ---------------------------------
 * 31:6  - SBZ
 * 5     - PD[1], whether misses in TTBR1 causes a table walk
 * 4     - PD[0], whether misses in TTBR0 causes a table walk
 * 3     - SBZ
 * 2:0   - N, split between TTBR0 and TTBR1
 */
  MOV     r0,#0x0    @  N=0 => no TTBR1 used
  MCR     p15, 0, r0, c2, c0, 2

  MOV PC, LR

/*
 * void secure_mmu_disable(void);
 */
secure_mmu_disable:
	MRC     p15, 0, R0, c1, c0, 0

	BIC     R0, R0, #CP15_CONTROL_M_MASK
	MCR     p15, 0, R0, c1, c0, 0

	DSB
	ISB

	MOV PC, LR

.equ SEC_MMU_TTB_FLD_SN_SHM      , 0x00011c02  @ 0x00011c0e to have memory cached
	                                           @ 0x00011c02 to have memory uncached

.equ SEC_MMU_TTB_FLD_SN_DEV      , 0x00001c02  @ device memory (iomem)

/* @ ; r0 = base address (physical address) */
/* @ ; Add a section of 1MBytes. */
/* @ ; Base address r0 is aligned on 1MB */
secure_mmu_addsection:

	MRC     p15, 0, R1, c2, c0 ,0		/* Get TTBR0 location */

	LSR     R0, R0, #20			 /* Clear bottom 20 bits, to find which 1MB block its in */
	LSL     R2, R0, #2			 /* Make a copy, and multiply by four.  This gives offset into the page tables */
	LSL     R0, R0, #20			 /* Put back in address format */

	LDR     R3, =SEC_MMU_TTB_FLD_SN_SHM	 /* Descriptor template */
	ORR     R0, R0, R3			 /* Combine address and template */
	STR     R0, [R1, R2]

	MOV     PC, LR

secure_mmu_addsectiondevice:

	MRC     p15, 0, R1, c2, c0 ,0		/* Get TTBR0 location */

	LSR     R0, R0, #20			/* Clear bottom 20 bits, to find which 1MB block its in */
	LSL     R2, R0, #2			/* Make a copy, and multiply by four.  This gives offset into the page tables */
	LSL     R0, R0, #20			/* Put back in address format */

	LDR     R3, =SEC_MMU_TTB_FLD_SN_DEV	/* Descriptor template */
	ORR     R0, R0, R3			/* Combine address and template */
	STR     R0, [R1, R2]

	MOV     PC, LR

secure_mmu_removesection:

	MRC     p15, 0, R1, c2, c0 ,0		/* Get TTBR0 location */

	LSR     R0, R0, #20			/* Clear bottom 20 bits, to find which 1MB block its in */
	LSL     R2, R0, #2			/* Make a copy, and multiply by four.  This gives offset into the page tables */
	LSL     R0, R0, #20			/* Put back in address format */

	MOV     R3, #0				/* Descriptor template */
	ORR     R0, R0, R3			/* Combine address and template */
	STR     R0, [R1, R2]

	MOV     PC, LR

.equ SEC_MMU_TTB_FLD_PT_SHM      , 0xbfed0001  @ Template descriptor

.equ SEC_MMU_TTB_SLD_SP_SHM      , 0x00000473  @ 0x0000047f to have memory cached
	                                           @ 0x00000433 to have memory strongly ordered
	                                           @ 0x00000473 to have memory uncached

/* @ ; r0 = base address (physical address) */
/* @ ; Add a section of 4KB. */
/* @ ; Base address r0 is aligned on 4KB */
secure_mmu_addsmallpage:
	PUSH    {R4, R5}

	LDR     R1, =SEC_MMU_TTB_SLD

	MOVW    R2, #0x0000
	MOVT    R2, #0xFFF0

	BIC     R2, R0, R2

	LSR      R2, R2, #12			/* Clear bottom 12 bits, to find which 4KB block its in */
	LSL      R2, R2, #2			/* Make a copy, and multiply by four.  This gives offset into the page tables */

	LDR      R3, =SEC_MMU_TTB_SLD_SP_SHM	/* Descriptor template */
	ORR      R0, R0, R3			/* Combine address and template */
	STR      R0, [R1, R2]

	LDR      R5, =SEC_MMU_TTB_SLD
	LDR      R4, [R5]

	MRC      p15, 0, R1, c2, c0 ,0		/* Get TTBR0 location */

	LSR      R0, R0, #20			/* Clear bottom 20 bits, to find which 1MB block its in */
	LSL      R2, R0, #2			/* Make a copy, and multiply by four.  This gives offset into the page tables */
	LSL      R0, R0, #20			/* Put back in address format */

	LDR      R3, =SEC_MMU_TTB_FLD_PT_SHM	/* Descriptor template */
	STR      R3, [R1, R2]

	POP    {R4, R5}
	MOV  PC, LR

secure_mmu_removesmallpage:

	LDR     R1, =SEC_MMU_TTB_SLD

	MOVW    R2, #0x0000
	MOVT    R2, #0xFFF0

	BIC     R2, R0, R2

	LSR     R2, R2, #12			/* Clear bottom 12 bits, to find which 4KB block its in */
	LSL     R2, R2, #2			/* Make a copy, and multiply by four.  This gives offset into the page tables */

	MOV     R3, #0				/* Descriptor template */
	ORR     R0, R0, R3			/* Combine address and template */
	STR     R0, [R1, R2]

	LDR     R5, =SEC_MMU_TTB_SLD
	LDR     R4, [R5]

	MRC    p15, 0, R1, c2, c0 ,0		/* Get TTBR0 location */

	LSR    R0, R0, #20			/* Clear bottom 20 bits, to find which 1MB block its in */
	LSL    R2, R0, #2			/* Make a copy, and multiply by four.  This gives offset into the page tables */
	LSL    R0, R0, #20			/* Put back in address format */

	LDR    R3, =SEC_MMU_TTB_FLD_PT_SHM	/* Descriptor template */
	STR    R3, [R1, R2]

	MOV    PC, LR

/*
 * - MMU maintenaince support ---------------------------------------------
 */

/*
 * void secure_mmu_datatlbinvall(void);
 */
secure_mmu_datatlbinvall:

	MCR     p15, 0, R0, c8, c6, 0

	DSB
	ISB

	MOV     PC, LR

/*
 * void secure_mmu_instrtlbinvall(void);
 */
secure_mmu_instrtlbinvall:

	MCR     p15, 0, R0, c8, c5, 0

	DSB
	ISB

	MOV     PC, LR

/*
 * void secure_mmu_unifiedtlbinvall(void);
 */
secure_mmu_unifiedtlbinvall:

	MCR     p15, 0, R0, c8, c7, 0

	DSB
	ISB

	MOV     PC, LR

/*
 * void secure_mmu_unifiedtlbinvbymva(mva);
 *
 * Combine VA and current ASID, and invalidate matching TLB
 */
secure_mmu_unifiedtlbinvbymva:

	b .	@ Wrong code to force fix/check the routine before using it

	MRC     p15, 0, R1, c13, c0, 1		/* Read CP15 Context ID Register (CONTEXTIDR) */
	ANDS    R1, R1, #0xFF			/* Get current ASID */
	ORR     R1, R1, R0			/* Combine MVA and ASID */

	MCR     p15, 0, R1, c8, c7, 1		/* Invalidate Unified TLB entry by MVA */

	DSB
	ISB

	MOV     PC, LR
/*
 * void secure_mmu_unifiedtlbinv_curasid(void)
 *
 * Invalidate TLB matching current ASID
 */
secure_mmu_unifiedtlbinv_curasid:

	MRC     p15, 0, R0, c13, c0, 1      /* Read CP15 Context ID Register (CONTEXTIDR) */
	AND     R0, R0, #0xFF               /* Get current ASID */
	MCR     p15, 0, R0, c8, c7, 2		/* Invalidate Unified TLB entry by ASID */
	DSB
	ISB
	MOV     PC, LR

/*
 * void secure_mmu_unifiedtlbinv_byasid(unsigned int asid)
 *
 * Invalidate TLB matching current ASID
 */
secure_mmu_unifiedtlbinv_byasid:

	AND     R0, R0, #0xFF               /* Get current ASID */
	MCR     p15, 0, R0, c8, c7, 2		/* Invalidate Unified TLB entry by ASID */
	DSB
	ISB
	MOV     PC, LR

/*
 * void arm_cl1_d_cleanbysetway(void)
 */
arm_cl1_d_cleanbysetway:

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

arm_cl1_d_invbysetway:

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

arm_cl1_d_cleaninvbysetway:

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

/*
 * void arm_cl1_d_cleanbypa(unsigned long s, unsigned long e);
 */
arm_cl1_d_cleanbypa:

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

/*
 * void arm_cl1_d_invbypa(unsigned long s, unsigned long e);
 */
arm_cl1_d_invbypa:

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

/*
 * void arm_cl1_d_cleaninvbypa(unsigned long s, unsigned long e);
 */
arm_cl1_d_cleaninvbypa:

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

/*
 * void arm_cl1_i_inv_all( void );
 *
 * Invalidates the whole instruction cache.
 * It also invalidates the BTAC.
 */
arm_cl1_i_inv_all:

    /* Invalidate Entire Instruction Cache */
    MOV     R0, #0
    MCR     p15, 0, R0, c7, c5, 0
    DSB

    /* Flush entire branch target cache */
    MOV     R1, #0
    MCR     p15, 0, R1, c7, c5, 6   /* write to Cache operations register */

    DSB                             /* ensure that maintenance operations are seen */
    ISB                             /* by the instructions rigth after the ISB */

    BX      LR

/*
 * void arm_cl1_i_inv(unsigned long start, unsigned long p_end);
 *
 * Invalidates instruction cache area whose (physical) limits are given in parameters.
 * It also invalidates the BTAC.
 */
arm_cl1_i_inv:

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
