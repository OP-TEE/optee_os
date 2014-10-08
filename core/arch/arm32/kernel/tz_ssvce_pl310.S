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

#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>

 /* cache maintenance */
.global arm_cl2_cleaninvbyway
.global arm_cl2_invbyway
.global arm_cl2_cleanbyway
.global arm_cl2_cleanbypa
.global arm_cl2_invbypa
.global arm_cl2_cleaninvbypa

/*
 * void arm_cl2_cleaninvbyway(void) - clean & invalidate the whole L2 cache.
 */
arm_cl2_cleaninvbyway:

	/* Clean and invalidate all cache ways */
	movw r0, #PL310_FLUSH_BY_WAY
	movt r0, PL310_BASE_H
	movw r1, #0x00FF
	movt r1, #0x0000
	str r1, [r0]

	/* Wait for all cache ways to be cleaned and invalidated */
loop_cli_way_done:
	ldr r2, [r0]
	and r2,r2,r1
	cmp r2, #0
	bne loop_cli_way_done

	/* Cache Sync */
	movw r0, #PL310_SYNC
	movt r0, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_cli_sync:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_cli_sync

	movw r1, #0x0001
	movt r1, #0x0000
	str r1, [r0]

loop_cli_sync_done:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_cli_sync_done

	mov pc, lr

/* void (arm_cl2_invbyway(void) */
arm_cl2_invbyway:

	/* Clean by Way */
	movw r0, #PL310_INV_BY_WAY
	movt r0, #PL310_BASE_H
	movw r1, #0x00FF	/* assumes here 8-way L2 cache (orly) */
	movt r1, #0x0000
	str r1, [r0]

	/* Wait end of Invalidate by Way */
loop_inv_way_done:
	ldr r2, [r0]
	and r2,r2,r1
	cmp r2, #0
	bne loop_inv_way_done

	/* Cache Sync */
	movw r0, #PL310_SYNC
	movt r0, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_inv_way_sync:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_inv_way_sync

	movw r1, #0x0001
	movt r1, #0x0000
	str r1, [r0]

	/* Wait end of Cache Sync */
loop_inv_way_sync_done:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_inv_way_sync_done

	mov pc, lr

/* void arm_cl2_cleanbyway(u32 pa) */
arm_cl2_cleanbyway:

	/* Clean by Way */
	movw r0, #PL310_CLEAN_BY_WAY
	movt r0, #PL310_BASE_H
	movw r1, #0x00FF
	movt r1, #0x0000
	str r1, [r0]

	/* Wait end of Clean by Way */
loop_cl_way_done:
	ldr r2, [r0]
	and r2,r2,r1
	cmp r2, #0
	bne loop_cl_way_done

	/* Cache Sync */
	movw r0, #PL310_SYNC
	movt r0, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_cl_way_sync:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_cl_way_sync

	movw r1, #0x0001
	movt r1, #0x0000
	str r1, [r0]

	/* Wait end of Cache Sync */
loop_cl_way_sync_done:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_cl_way_sync_done

	mov pc, lr

/*
 * void arm_cl2_cleanbypa(unsigned long start, unsigned long end);
 *
 * clean L2 cache by physical address range.
 */
arm_cl2_cleanbypa:

	/*
	 * ARM ERRATA #764369
	 * Undocummented SCU Diagnostic Control Register
	 */
	MOVW R2, #SCU_ERRATA744369 /* LSB */
	MOVT R2, #SCU_BASE_H /* MSB */
	MOVW R3, #0x0001
	MOVT R3, #0x0000
	STR R3, [R2]
	DSB

	/* Clean PA */
loop_cl2_clean_by_pa:
	movw R2, #PL310_CLEAN_BY_PA
	movt R2, #PL310_BASE_H
	str R0, [R2]

	/* Wait for PA to be cleaned */
loop_cl_pa_done:
	ldr R3, [R2]
	and R3,R3,R0
	cmp R3, #0
	bne loop_cl_pa_done

	add R0, R0, #32
	cmp R1, R0
	bne loop_cl2_clean_by_pa

	/* Cache Sync */
	movw R2, #PL310_SYNC
	movt R2, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_cl_pa_sync:
	ldr R0, [R2]
	cmp R0, #0
	bne loop_cl_pa_sync

	movw R0, #0x0001
	movt R0, #0x0000
	str R0, [R2]

loop_cl_pa_sync_done:
	ldr R0, [R2]
	cmp R0, #0
	bne loop_cl_pa_sync_done

	mov pc, lr

/*
 * void arm_cl2_invbypa(unsigned long start, unsigned long end);
 *
 * invalidate L2 cache by physical address range.
 */
arm_cl2_invbypa:

	/*
	 * ARM ERRATA #764369
	 * Undocummented SCU Diagnostic Control Register
	 */
	MOVW R2, #SCU_ERRATA744369 /* LSB */
	MOVT R2, #SCU_BASE_H /* MSB */
	MOVW R3, #0x0001
	MOVT R3, #0x0000
	STR R3, [R2]
	DSB

	/* Invalidate PA */
loop_cl2_inv_by_pa:
	MOVW R2, #PL310_INV_BY_PA
	MOVT R2, #PL310_BASE_H
	STR R0, [R2]

	/* Wait for PA to be invalidated */
loop_inv_pa_done:
	LDR R3, [R2]
	AND R3,R3,R0
	CMP R3, #0
	BNE loop_inv_pa_done

	ADD R0, R0, #32
	CMP R1, R0
	BNE loop_cl2_inv_by_pa


	/* Cache Sync */
	MOVW R2, #PL310_SYNC
	MOVT R2, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_inv_pa_sync:
	LDR R0, [R2]
	CMP R0, #0
	BNE loop_inv_pa_sync

	MOVW R0, #0x0001
	MOVT R0, #0x0000
	STR R0, [R2]

loop_inv_pa_sync_done:
	LDR R0, [R2]
	CMP R0, #0
	BNE loop_inv_pa_sync_done

	MOV PC, LR

/*
 * void arm_cl2_cleaninvbypa(unsigned long start, unsigned long end);
 *
 * clean and invalidate L2 cache by physical address range.
 */
arm_cl2_cleaninvbypa:

	mov r2, r0
	/*
	 * ARM ERRATA #764369
	 * Undocummented SCU Diagnostic Control Register
	 */
	MOVW R0, #SCU_ERRATA744369 /* LSB */
	MOVT R0, #SCU_BASE_H /* MSB */
	mov r1, #1
	STR R1, [R0]
	DSB

	/* Invalidate PA */
	movw r0, #PL310_FLUSH_BY_PA
	movt r0, #PL310_BASE_H
	str r2, [r0]

	/* Wait for PA to be invalidated */
loop_cli_pa_done:
	ldr r2, [r0]
	and r2,r2,r1
	cmp r2, #0
	bne loop_cli_pa_done

	/* Cache Sync */
	movw r0, #PL310_SYNC
	movt r0, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_cli_pa_sync:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_cli_pa_sync

	mov r1, #1
	str r1, [r0]

loop_cli_pa_sync_done:
	ldr r1, [r0]
	cmp r1, #0
	bne loop_cli_pa_sync_done

	mov pc, lr
