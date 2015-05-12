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
#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>

#define CPUID_A9_R3P0_H 0x413f
#define CPUID_A9_R3P0_L 0xc090

/*
 * Memory Cache Level2 Configuration Function
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC arm_cl2_config , :
	mrc  p15, 0, r0, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r0, r1
	beq  _config_l2cc_r3p0
	b . /* TODO: unknown id: reset? log? */

_config_l2cc_r3p0:
	/*
	 * TAG RAM Control Register
	 *
	 * bit[10:8]:1 - 2 cycle of write accesses latency
	 * bit[6:4]:1 - 2 cycle of read accesses latency
	 * bit[2:0]:1 - 2 cycle of setup latency
	 */
	movw r0, #PL310_TAG_RAM_CTRL
	movt r0, #PL310_BASE_H
	ldr  r2, [r0]
	movw r1, #0xf888
	movt r1, #0xffff
	and  r2,r2,r1
	movw r1, #0xf999
	movt r1, #0xffff
	orr  r2,r2,r1
	str  r2, [r0]

	/*
	 * DATA RAM Control Register
	 *
	 * bit[10:8]:2 - 3 cycle of write accesses latency
	 * bit[6:4]:2 - 3 cycle of read accesses latency
	 * bit[2:0]:2 - 3 cycle of setup latency
	 */
	movw r0, #PL310_DATA_RAM_CTRL
	movt r0, #PL310_BASE_H
	ldr  r2, [r0]
	movw r1, #0xf888
	movt r1, #0xffff
	and  r2,r2,r1
	movw r1, #0xfaaa
	movt r1, #0xffff
	orr  r2,r2,r1
	str  r2, [r0]

	/*
	 * Auxiliary Control Register = 0x3C480800
	 *
	 * I/Dcache prefetch enabled (bit29:28=2b11)
	 * NS can access interrupts (bit27=1)
	 * NS can lockown cache lines (bit26=1)
	 * Pseudo-random replacement policy (bit25=0)
	 * Force write allocated (default)
	 * Shared attribute internally ignored (bit22=1, bit13=0)
	 * Parity disabled (bit21=0)
	 * Event monitor disabled (bit20=0)
	 * 128kB ways, 8-way associativity (bit19:17=3b100 bit16=0)
	 * Store buffer device limitation enabled (bit11=1)
	 * Cacheable accesses have high prio (bit10=0)
	 * Full Line Zero (FLZ) disabled (bit0=0)
	 */
	movw r0, #PL310_AUX_CTRL
	movt r0, #PL310_BASE_H
	movw r1, #0x0800
	movt r1, #0x3C48
	str  r1, [r0]

	/*
	 * Prefetch Control Register = 0x31000007
	 *
	 * Double linefill disabled (bit30=0)
	 * I/D prefetch enabled (bit29:28=2b11)
	 * Prefetch drop enabled (bit24=1)
	 * Incr double linefill disable (bit23=0)
	 * Prefetch offset = 7 (bit4:0)
	 */
	movw r0, #PL310_PREFETCH_CTRL
	movt r0, #PL310_BASE_H
	movw r1, #0x0007
	movt r1, #0x3100
	str  r1, [r0]

	/*
	 * Power Register = 0x00000003
	 *
	 * Dynamic clock gating enabled
	 * Standby mode enabled
	 */
	movw r0, #PL310_POWER_CTRL
	movt r0, #PL310_BASE_H
	movw r1, #0x0003
	movt r1, #0x0000
	str  r1, [r0]

	/* invalidate all cache ways */
	movw r0, #PL310_INV_BY_WAY
	movt r0, #PL310_BASE_H
	movw r1, #0x00FF
	movt r1, #0x0000
	str  r1, [r0]

	mov pc, lr
END_FUNC arm_cl2_config

/*
 * Memory Cache Level2 Enable Function
 *
 * If PL310 supports FZLW, enable also FZL in A9 core
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC arm_cl2_enable , :
	/* Enable PL310 ctrl -> only set lsb bit */
	movw r0, #PL310_CTRL
	movt r0, #PL310_BASE_H
	mov  r1, #0x1
	str  r1, [r0]

	/* if L2 FLZW enable, enable in L1 */
	movw r0, #PL310_AUX_CTRL
	movt r0, #PL310_BASE_H
	ldr  r1, [r0]
	tst  r1, #(1 << 0) /* test AUX_CTRL[FLZ] */
	mrc  p15, 0, r0, c1, c0, 1
	orrne r0, r0, #(1 << 3) /* enable ACTLR[FLZW] */
	mcr  p15, 0, r0, c1, c0, 1

	mov pc, lr
END_FUNC arm_cl2_enable


/* lock all L2 caches ways for data and instruction */
FUNC arm_cl2_lockallways , :

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
END_FUNC arm_cl2_lockallways
/*
 * void arm_cl2_cleaninvbyway(void) - clean & invalidate the whole L2 cache.
 */
FUNC arm_cl2_cleaninvbyway , :

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
END_FUNC arm_cl2_cleaninvbyway

/* void (arm_cl2_invbyway(void) */
FUNC arm_cl2_invbyway , :

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
END_FUNC arm_cl2_invbyway

/* void arm_cl2_cleanbyway(u32 pa) */
FUNC arm_cl2_cleanbyway , :

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
END_FUNC arm_cl2_cleanbyway

/*
 * void _arm_cl2_xxxbypa(paddr_t start, paddr_t end, int pl310value);
 * pl310value is one of PL310_CLEAN_BY_PA, PL310_INV_BY_PA or PL310_FLUSH_BY_PA
 */
LOCAL_FUNC _arm_cl2_xxxbypa , :
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
END_FUNC _arm_cl2_xxxbypa

/*
 * void _arm_cl2_cleanbypa(paddr_t start, paddr_t end);
 * clean L2 cache by physical address range.
 */
FUNC arm_cl2_cleanbypa , :
	movw r2, #PL310_CLEAN_BY_PA
	movt r2, #PL310_BASE_H
	b _arm_cl2_xxxbypa
END_FUNC arm_cl2_cleanbypa

/*
 * void arm_cl2_invbypa(paddr_t start, paddr_t end);
 * invalidate L2 cache by physical address range.
 */
FUNC arm_cl2_invbypa , :
	movw r2, #PL310_INV_BY_PA
	movt r2, #PL310_BASE_H
	b _arm_cl2_xxxbypa
END_FUNC arm_cl2_invbypa

/*
 * void arm_cl2_cleaninvbypa(paddr_t start, paddr_t end);
 * clean and invalidate L2 cache by physical address range.
 */
FUNC arm_cl2_cleaninvbypa , :
	movw r2, #PL310_FLUSH_BY_PA
	movt r2, #PL310_BASE_H
	b _arm_cl2_xxxbypa
END_FUNC arm_cl2_cleaninvbypa
