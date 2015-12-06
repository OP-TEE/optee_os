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
#include <asm.S>
#include <kernel/unwind.h>

/* lock all L2 caches ways for data and instruction */
FUNC arm_cl2_lockallways , :
UNWIND(	.fnstart)

	mov r0, #PL310_NB_WAYS
	movw r1, #PL310_DCACHE_LOCKDOWN_BASE
	movt r1, #PL310_BASE_H
	movw r2, #0xFFFF	/* LD ways constant */
loop_data_lockdown:
	str r2, [r1], #0x04	/* lock way for Dcache */
	str r2, [r1], #0x04	/* lock way for Icache  */
	subs r0, r0, #1
	bne loop_data_lockdown

	mov pc, lr
UNWIND(	.fnend)
END_FUNC arm_cl2_lockallways

/*
 * void arm_cl2_cleaninvbyway(void) - clean & invalidate the whole L2 cache.
 */
FUNC arm_cl2_cleaninvbyway , :
UNWIND(	.fnstart)

	/* Clean and invalidate all cache ways */
	movw r0, #PL310_FLUSH_BY_WAY
	movt r0, #PL310_BASE_H
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
UNWIND(	.fnend)
END_FUNC arm_cl2_cleaninvbyway

/* void (arm_cl2_invbyway(void) */
FUNC arm_cl2_invbyway , :
UNWIND(	.fnstart)

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
UNWIND(	.fnend)
END_FUNC arm_cl2_invbyway

/* void arm_cl2_cleanbyway(u32 pa) */
FUNC arm_cl2_cleanbyway , :
UNWIND(	.fnstart)

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
UNWIND(	.fnend)
END_FUNC arm_cl2_cleanbyway

/*
 * void _arm_cl2_xxxbypa(paddr_t start, paddr_t end, int pl310value);
 * pl310value is one of PL310_CLEAN_BY_PA, PL310_INV_BY_PA or PL310_FLUSH_BY_PA
 */
LOCAL_FUNC _arm_cl2_xxxbypa , :
UNWIND(	.fnstart)
	/* Align start address on PL310 line size */
	and r0, #(~(PL310_LINE_SIZE - 1))

	/*
	 * ARM ERRATA #764369
	 * Undocummented SCU Diagnostic Control Register
	 */
	movw r12, #SCU_ERRATA744369 /* LSB */
	movt r12, #SCU_BASE_H /* MSB */
	movw r3, #0x0001
	movt r3, #0x0000
	str r3, [r12]
	dsb

loop_cl2_xxxbypa:
	mov r12, r2
	str r0, [r12]

	/* Wait for PA to be cleaned */
loop_xxx_pa_done:
	ldr r3, [r12]
	and r3,r3,r0
	cmp r3, #0
	bne loop_xxx_pa_done

	add r0, r0, #PL310_LINE_SIZE
	cmp r1, r0
	bpl loop_cl2_xxxbypa

	/* Cache Sync */
	movw r12, #PL310_SYNC
	movt r12, #PL310_BASE_H

	/* Wait for writing cache sync */
loop_xxx_pa_sync:
	ldr r0, [r12]
	cmp r0, #0
	bne loop_xxx_pa_sync

	movw r0, #0x0001
	movt r0, #0x0000
	str r0, [r12]

loop_xxx_pa_sync_done:
	ldr r0, [r12]
	cmp r0, #0
	bne loop_xxx_pa_sync_done

	mov pc, lr
UNWIND(	.fnend)
END_FUNC _arm_cl2_xxxbypa

/*
 * void _arm_cl2_cleanbypa(paddr_t start, paddr_t end);
 * clean L2 cache by physical address range.
 */
FUNC arm_cl2_cleanbypa , :
UNWIND(	.fnstart)
	movw r2, #PL310_CLEAN_BY_PA
	movt r2, #PL310_BASE_H
	b _arm_cl2_xxxbypa
UNWIND(	.fnend)
END_FUNC arm_cl2_cleanbypa

/*
 * void arm_cl2_invbypa(paddr_t start, paddr_t end);
 * invalidate L2 cache by physical address range.
 */
FUNC arm_cl2_invbypa , :
UNWIND(	.fnstart)
	movw r2, #PL310_INV_BY_PA
	movt r2, #PL310_BASE_H
	b _arm_cl2_xxxbypa
UNWIND(	.fnend)
END_FUNC arm_cl2_invbypa

/*
 * void arm_cl2_cleaninvbypa(paddr_t start, paddr_t end);
 * clean and invalidate L2 cache by physical address range.
 */
FUNC arm_cl2_cleaninvbypa , :
UNWIND(	.fnstart)
	movw r2, #PL310_FLUSH_BY_PA
	movt r2, #PL310_BASE_H
	b _arm_cl2_xxxbypa
UNWIND(	.fnend)
END_FUNC arm_cl2_cleaninvbypa

