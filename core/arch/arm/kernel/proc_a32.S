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

#include <kernel/tz_proc.h>
#include <kernel/tz_proc_def.h>
#include <kernel/unwind.h>
#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>

	.section .text.proc

/* void cpu_spin_lock(lock address) - lock mutex */
FUNC cpu_spin_lock , :
UNWIND(	.fnstart)
	mov r2, #SPINLOCK_LOCK
_spinlock_loop:
	ldrex r1, [r0]
	cmp r1, #SPINLOCK_UNLOCK
	wfene
	bne _spinlock_loop
	strex r1, r2, [r0]
	cmp r1, #0
	wfene
	bne _spinlock_loop
	dmb
	bx lr
UNWIND(	.fnend)
END_FUNC cpu_spin_lock

/* int cpu_spin_trylock(lock address) - return 0 on success */
FUNC cpu_spin_trylock , :
UNWIND(	.fnstart)
	mov r2, #SPINLOCK_LOCK
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
UNWIND(	.fnend)
END_FUNC cpu_spin_trylock

/* void cpu_spin_unlock(lock address) - unlock mutex */
FUNC cpu_spin_unlock , :
UNWIND(	.fnstart)
	dmb
	mov r1, #SPINLOCK_UNLOCK
	str r1, [r0]
	dsb
	sev
	bx lr
UNWIND(	.fnend)
END_FUNC cpu_spin_unlock

/*
 * void cpu_mmu_enable(void) - enable MMU
 *
 * TLBs are invalidated before MMU is enabled.
 * An DSB and ISB insures MMUs is enabled before routine returns
 */
FUNC cpu_mmu_enable , :
UNWIND(	.fnstart)
	/* Invalidate TLB */
	write_tlbiall

	/* Enable the MMU */
	read_sctlr r0
	orr	r0, r0, #SCTLR_M
	write_sctlr r0

	dsb
	isb

	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_mmu_enable

/* void cpu_mmu_enable_icache(void) - enable instruction cache */
FUNC cpu_mmu_enable_icache , :
UNWIND(	.fnstart)
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
UNWIND(	.fnend)
END_FUNC cpu_mmu_enable_icache

/* void cpu_mmu_enable_dcache(void) - enable data cache */
FUNC cpu_mmu_enable_dcache , :
UNWIND(	.fnstart)
	read_sctlr r0
	orr	r0, r0, #SCTLR_C
	write_sctlr r0

	dsb
	isb

	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_mmu_enable_dcache
