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
 * Include(s)
 */
#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>
#include <platform_config.h>

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <sm/teesmc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>

.section .data
.balign 4

#ifdef CFG_BOOT_SYNC_CPU
/*
 * Semaphore to let primary CPU runs its inits
 * before secondary CPUs run their own inits
 */
/* Semaphores sync CPU0 and CPU1 */
.equ SEM_NOT_READY, 2
.equ SEM_CPU_READY, 4

sem_cpu_sync:
	.word SEM_NOT_READY;	/* cpu0 */
	.word SEM_NOT_READY;	/* cpu1 */
	.word SEM_NOT_READY;	/* cpu2 */
	.word SEM_NOT_READY;	/* cpu3 */
	.word SEM_NOT_READY;	/* cpu4 */
	.word SEM_NOT_READY;	/* cpu5 */
	.word SEM_NOT_READY;	/* cpu6 */
	.word SEM_NOT_READY;	/* cpu7 */
#endif

#ifdef CFG_TEE_GDB_BOOT
gdb_bootargs:
	.word 0
	.word 0
	.word 0
	.word 0
#endif

.section .text.boot
FUNC _start , :
	b	reset
	b	.	/* Undef */
	b	.	/* Syscall */
	b	.	/* Prefetch abort */
	b	.	/* Data abort */
	b	.	/* Reserved */
	b	.	/* IRQ */
	b	.	/* FIQ */
END_FUNC _start

/* Let platforms override this if needed */
.weak arm_secboot_early
.weak arm_secboot_late

/*
 * Enable alignment checks and disable data and instruction cache.
 */
FUNC arm_secboot_early , :
	read_sctlr r0
	orr	r0, r0, #SCTLR_A
	bic	r0, r0, #SCTLR_C
	bic	r0, r0, #SCTLR_I
	write_sctlr r0
	bx	lr
END_FUNC arm_secboot_early

FUNC arm_secboot_late , :
	bx	lr
END_FUNC arm_secboot_late

#ifdef CFG_BOOT_SYNC_CPU
LOCAL_FUNC cpu_is_ready , :
	lsl	r0, r0, #2
	ldr	r1,=sem_cpu_sync
	ldr	r2, =SEM_CPU_READY
	str	r2, [r1, r0]
	dsb
	sev
	bx	lr
END_FUNC cpu_is_ready

LOCAL_FUNC wait_primary , :
	ldr	r0, =sem_cpu_sync
	mov	r2, #SEM_CPU_READY
	sev
_wait_cpu0:
	ldr	r1, [r0]
	cmp	r1, r2
	wfene
	bne	_wait_cpu0
	bx	lr
END_FUNC wait_primary

LOCAL_FUNC wait_secondary , :
	ldr	r0, =sem_cpu_sync
	mov	r3, #CFG_TEE_CORE_NB_CORE
	mov	r2, #SEM_CPU_READY
	sev
_wait_next:
	subs	r3, r3, #1
	beq	_synced_cpun
	add	r0, r0, #4
_wait_cpun:
	ldr	r1, [r0]
	cmp	r1, r2
	wfene
	bne	_wait_cpun
	b	_wait_next
_synced_cpun:
	bx	lr
END_FUNC wait_secondary

#else
/*
 * CFG_BOOT_SYNC_CPU is not defined
 * So cpu synchronization functions are empty
 */
LOCAL_FUNC cpu_is_ready , :
	bx	lr
END_FUNC cpu_is_ready

LOCAL_FUNC wait_primary , :
	bx	lr
END_FUNC wait_primary

LOCAL_FUNC wait_secondary , :
	bx	lr
END_FUNC wait_secondary
#endif

LOCAL_FUNC reset , :
	mov	r4, r0		/* Save pageable part address */
	mov	r5, lr		/* Save ns-entry address */

#ifdef CFG_TEE_GDB_BOOT
	/* boot preloaded linux: save linux boot args from GDB */
	mov r10, r0
	mov r11, r1
	mov r12, r2
	/* all following routines, until stack is setup, preserve R10/R11/R12 */
#endif

	/*
	 * Enable alignment checks and disable data and instruction cache.
	 */
	bl arm_secboot_early

	ldr	r0, =_start
	write_vbar r0

	bl	get_core_pos
	cmp	r0, #0
	beq	reset_primary
	b	reset_secondary
END_FUNC reset

LOCAL_FUNC reset_primary , :
	bl	get_core_pos
	cmp	r0, #CFG_TEE_CORE_NB_CORE
	/* Unsupported CPU, park it before it breaks something */
	bge	unhandled_cpu
	lsl	r0, #2
	ldr	r1, =stack_tmp_top
	ldr	sp, [r1, r0]

	/* complete ARM secure MP common configuration */
	bl arm_secboot_late

#ifdef CFG_TEE_GDB_BOOT
	ldr r0, =gdb_bootargs
	str r10, [r0, #0]
	str r11, [r0, #4]
	str r12, [r0, #8]
#endif

	/* Enable Console */
	bl	console_init

#ifdef CFG_PL310
	bl	arm_cl2_config
#endif

	/*
	 * Invalidate dcache for all memory used during initialization to
	 * avoid nasty surprices when the cache is turned on. We must not
	 * invalidate memory not used by OP-TEE since we may invalidate
	 * entries used by for instance ARM Trusted Firmware.
	 *
	 * Before MMU is turned on is VA == PA for cache operations.
	 */
	ldr	r0, =__text_start
#ifdef CFG_WITH_PAGER
	ldr	r1, =__init_end
#else
	ldr	r1, =_end
#endif
	sub	r1, r1, #1
	bl	arm_cl1_d_invbyva

#ifdef CFG_PL310
	ldr	r0, =__text_start
#ifdef CFG_WITH_PAGER
	ldr	r1, =__init_end
#else
	ldr	r1, =_end
#endif
	sub	r1, r1, #1
	bl	arm_cl2_invbypa

	bl	arm_cl2_enable
#endif

	bl	core_init_mmu_map
	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	r0, r4		/* pageable part address */
	mov	r1, r5		/* ns-entry address */
	bl	generic_boot_init_primary

	bl	get_core_pos
	bl	cpu_is_ready

	/*
	 * In case we've touched memory that secondary CPUs will use before
	 * they have turned on their D-cache, clean and invalidate the
	 * D-cache before exiting to normal world.
	 */
	ldr	r0, =__text_start
#ifdef CFG_WITH_PAGER
	ldr	r1, =__init_end
#else
	ldr	r1, =_end
#endif
	sub	r1, r1, #1
	bl	arm_cl1_d_cleaninvbyva

#ifdef CFG_PL310
	ldr	r0, =__text_start
#ifdef CFG_WITH_PAGER
	ldr	r1, =__init_end
#else
	ldr	r1, =_end
#endif
	sub	r1, r1, #1
	bl	arm_cl2_cleaninvbypa

#endif

#ifdef CFG_PL310_LOCKED
	bl	arm_cl2_lockallways
	bl	arm_cl2_invbyway
#endif

	bl	wait_secondary

#ifdef CFG_TEE_GDB_BOOT
	/* restore linux boot arguments */
	ldr r4, =gdb_bootargs
	ldr r1, [r4, #0]
	ldr r2, [r4, #4]
	ldr r3, [r4, #8]
#else
	mov	r1, #0
	mov	r2, #0
	mov	r3, #0
#endif

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC reset_primary


LOCAL_FUNC unhandled_cpu , :
	wfi
	b	unhandled_cpu
END_FUNC unhandled_cpu

LOCAL_FUNC reset_secondary , :
	bl	wait_primary

	bl	get_core_pos
	cmp	r0, #CFG_TEE_CORE_NB_CORE
	/* Unsupported CPU, park it before it breaks something */
	bge	unhandled_cpu
	lsl	r0, #2
	ldr	r1, =stack_tmp_top
	ldr	sp, [r1, r0]

	bl	arm_secboot_late

	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	bl	get_core_pos
	bl	cpu_is_ready

	mov	r0, r5		/* ns-entry address */
	bl	generic_boot_init_secondary

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	mov	r1, #0
	mov	r2, #0
	mov	r3, #0
	smc	#0
	b	.	/* SMC should not return */
END_FUNC reset_secondary
