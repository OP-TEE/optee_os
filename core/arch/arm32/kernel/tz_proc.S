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
 * ARMv7 core support routines
 */

#include <kernel/tz_proc_def.h>

.global cpu_dsb
.global cpu_dmb
.global cpu_isb
.global cpu_wfe
.global cpu_sev
.global cpu_disable_its
.global cpu_enable_its
.global cpu_read_cpsr
.global cpu_write_cpsr
.global cpu_read_ttbr0
.global cpu_write_ttbr0
.global cpu_spin_lock
.global cpu_spin_trylock
.global cpu_spin_unlock
.global mmu_enable @ CeCh ADD
.global mmu_enable_icache @ CeCh ADD
.global mmu_enable_dcache @ CeCh ADD

.section .text
.balign 4
.code 32

/* void cpu_dmb(void); */
cpu_dmb:
    dmb
    bx lr

/* void cpu_dsb(void); */
cpu_dsb:
    dsb
    bx lr

/* void cpu_isb(void); */
cpu_isb:
    isb
    bx lr

/* void cpu_wfe(void); */
cpu_wfe:
    wfe
    bx lr

/* void cpu_sev(void); */
cpu_sev:
    sev
    bx lr

/* void cpu_disable_its(void) - disable local core interruptions */
cpu_disable_its:
    cpsid if
    mov pc, lr

/* void cpu_enable_its(void) - enable local core interruptions */
cpu_enable_its:
    cpsie if
    mov pc, lr

/* unsigned int cpu_read_cpsr(void) - return CPRS in R0 */
cpu_read_cpsr:
    MRS R0, CPSR
    BX LR

/* void cpu_write_cpsr(cpsr) - write R0 content to CPSR */
cpu_write_cpsr:
    MSR CPSR_cxsf, R0
    BX LR

/* uint32_t cpu_read_ttbr0(void) - read CP15 TTBR0 */
cpu_read_ttbr0:
    mrc p15, 0, r0, c2, c0 ,0
    bx lr

/* void cpu_write_ttbr0(uint32_t ttbr0) - write CP15 TTBR0 */
cpu_write_ttbr0:
    mcr p15, 0, r0, c2, c0 ,0
    bx lr

/* void cpu_spin_lock(lock address) - lock mutex */
cpu_spin_lock:
    mov r2, #LOCK
_spinlock_loop:
    ldrex r1, [r0]
    cmp r1, #UNLOCK
    wfene
    bne _spinlock_loop
    strex r1, r2, [r0]
    cmp r1, #0
    wfene
    bne _spinlock_loop
    dmb
    bx lr

/* int cpu_spin_trylock(lock address) - return 0 on success */
cpu_spin_trylock:
    mov r2, #LOCK
    mov r1, r0
_trylock_loop:
    ldrex r0, [r1]
    cmp r0, #0
    bne _trylock_out
    strex r0, r2, [r1]
    cmp r0, #0
    bne _trylock_loop
    dmb
    bx lr
_trylock_out:
    clrex
    dmb
    bx lr

/* void cpu_spin_unlock(lock address) - unlock mutex */
cpu_spin_unlock:
    dmb
    mov r1, #UNLOCK
    str r1, [r0]
    dsb
    sev
    bx lr

/*
 * void mmu_enable(void) - enable MMU
 *
 * TLBs are invalidated before MMU is enabled.
 * An DSB and ISB insures MMUs is enabled before routine returns
 */
mmu_enable:
     
    MCR     p15, 0, R0, c8, c7, 0
   
    MRC     p15, 0, R0, c1, c0, 0
   
    ORR     R0, R0, #CP15_CONTROL_M_MASK
    MCR     p15, 0, R0, c1, c0, 0
       
    DSB
    ISB

    MOV PC, LR

/* void mmu_enable_icache(void) - enable instruction cache */
mmu_enable_icache:

    MOV     R1, #0
    MCR     p15, 0, R1, c7, c5, 0 		/* write to Cache operations register */

    MOV     R1, #0
    MCR     p15, 0, R1, c7, c5, 6 		/* write to Cache operations register */

    MRC     p15, 0, R1, c1, c0 , 0         	/* read control reg */
    ORR     R1, R1, #CP15_CONTROL_I_MASK    	/* set ICache enable bit */
    MCR     p15, 0, R1, c1, c0 , 0         	/* write control reg */

    DSB
    ISB

    MOV PC, LR

/* void mmu_enable_dcache(void) - enable data cache */
mmu_enable_dcache:

   PUSH    {R4,LR}
   

    MRC     p15,  0, R1, c1, c0 , 0         /* read control reg */
    ORR     R1, R1, #CP15_CONTROL_C_MASK    /* set DCache enable bit */
    MCR     p15,  0, R1, c1, c0 , 0         /* write control reg */
   
    DSB
    ISB

    POP     {R4,PC}
