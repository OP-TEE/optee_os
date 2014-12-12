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
#include <asm.S>
#include <arm32.h>
#include <arm32_macros.S>

.global cpu_spin_lock
.global cpu_spin_trylock
.global cpu_spin_unlock
.global cpu_mmu_enable
.global cpu_mmu_va2pa
.global cpu_mmu_enable_icache
.global cpu_mmu_enable_dcache

.section .text
.balign 4
.code 32

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
 * void cpu_mmu_enable(void) - enable MMU
 *
 * TLBs are invalidated before MMU is enabled.
 * An DSB and ISB insures MMUs is enabled before routine returns
 */
FUNC cpu_mmu_enable , :
	/* Invalidate TLB */
	write_tlbiall

	/* Enable the MMU */
	read_sctlr r0
	orr	r0, r0, #SCTLR_M
	write_sctlr r0

	dsb
	isb

	bx	lr
END_FUNC cpu_mmu_enable
/*
 * int cpu_mmu_va2pa(unsigned int id, unsigned int va, unsigned int *pa);
 * TODO: mask out the 12 LSB of input virt addr and mask in the output pa.
 */
cpu_mmu_va2pa:

	cmp r2, #0
	beq _va2pa_err
	cmp r0, #CPU_V2P_SEC_PRIV_RD
	beq _va2pa_pr
	cmp r0, #CPU_V2P_SEC_PRIV_WR
	beq _va2pa_pw
	cmp r0, #CPU_V2P_SEC_USR_RD
	beq _va2pa_ur
	cmp r0, #CPU_V2P_SEC_USR_WR
	beq _va2pa_uw
_va2pa_err:
	mov r0, #1
	mov pc, lr
_va2pa_pr:
	mcr p15, 0, r1, c7, c8, 0
	b _va2pa_end
_va2pa_pw:
	mcr p15, 0, r1, c7, c8, 1
	b _va2pa_end
_va2pa_ur:
	mcr p15, 0, r1, c7, c8, 2
	b _va2pa_end
_va2pa_uw:
	mcr p15, 0, r1, c7, c8, 3
_va2pa_end:
	mrc p15, 0, r0, c7, c4, 0
	str r0, [r2]
	tst r0, #1
	moveq r0, #0
	movne r0, #1
_va2pa_out:
	mov pc, lr


/* void cpu_mmu_enable_icache(void) - enable instruction cache */
FUNC cpu_mmu_enable_icache , :
	/* Invalidate instruction cache and branch predictor */
	write_iciallu
	write_bpiall

	/* Enable the instruction cache */
	read_sctlr r1
	orr	r1, r1, #SCTLR_I
	write_sctlr r1

	dsb
	isb

	bx	lr
END_FUNC cpu_mmu_enable_icache

/* void cpu_mmu_enable_dcache(void) - enable data cache */
FUNC cpu_mmu_enable_dcache , :
	read_sctlr r0
	orr	r0, r0, #SCTLR_C
	write_sctlr r0

	dsb
	isb

	bx	lr
END_FUNC cpu_mmu_enable_dcache
