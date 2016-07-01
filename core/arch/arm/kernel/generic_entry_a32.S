/*
 * Copyright (c) 2014, Linaro Limited
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

#include <platform_config.h>

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>
#include <kernel/unwind.h>

.section .data
.balign 4

#ifdef CFG_BOOT_SYNC_CPU
.equ SEM_CPU_READY, 1
#endif

#ifdef CFG_TEE_GDB_BOOT
gdb_bootargs:
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
.weak plat_cpu_reset_early
FUNC plat_cpu_reset_early , :
UNWIND(	.fnstart)
	bx	lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_early

.weak plat_cpu_reset_late
FUNC plat_cpu_reset_late , :
UNWIND(	.fnstart)
	bx	lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_late

#ifdef CFG_BOOT_SYNC_CPU
LOCAL_FUNC cpu_is_ready , :
UNWIND(	.fnstart)
	lsl	r0, r0, #2
	ldr	r1,=sem_cpu_sync
	ldr	r2, =SEM_CPU_READY
	str	r2, [r1, r0]
	dsb
	sev
	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_is_ready

LOCAL_FUNC wait_primary , :
UNWIND(	.fnstart)
	ldr	r0, =sem_cpu_sync
	mov	r2, #SEM_CPU_READY
	sev
_wait_cpu0:
	ldr	r1, [r0]
	cmp	r1, r2
	wfene
	bne	_wait_cpu0
	bx	lr
UNWIND(	.fnend)
END_FUNC wait_primary

LOCAL_FUNC wait_secondary , :
UNWIND(	.fnstart)
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
UNWIND(	.fnend)
END_FUNC wait_secondary

#else
/*
 * CFG_BOOT_SYNC_CPU is not defined
 * So cpu synchronization functions are empty
 */
LOCAL_FUNC cpu_is_ready , :
UNWIND(	.fnstart)
	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_is_ready

LOCAL_FUNC wait_primary , :
UNWIND(	.fnstart)
	bx	lr
UNWIND(	.fnend)
END_FUNC wait_primary

LOCAL_FUNC wait_secondary , :
UNWIND(	.fnstart)
	bx	lr
UNWIND(	.fnend)
END_FUNC wait_secondary
#endif

LOCAL_FUNC reset , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mov	r4, r0		/* Save pageable part address */
	mov	r5, lr		/* Save ns-entry address */
	mov	r6, r2		/* Save DT address */

#ifdef CFG_TEE_GDB_BOOT
	/*
	 * boot preloaded linux: save linux boot args from GDB
	 * all following routines, until reset_primary is called,
	 * preserve r6/r7/r8
	 */
	mov	r6, r0
	mov	r7, r1
	mov	r8, r2
#if defined(CFG_WITH_PAGER) || defined (CFG_DT)
	/*
	 * r0/r2 are used for different purposes by GDB boot and pager/DT
	 * so these configurations are incompatible
	 */
#error CFG_TEE_GDB_BOOT and (CFG_WITH_PAGER || CFG_DT) are incompatible
#endif
#endif

	/* Enable alignment checks and disable data and instruction cache. */
	read_sctlr r0
	orr	r0, r0, #SCTLR_A
	bic	r0, r0, #SCTLR_C
	bic	r0, r0, #SCTLR_I
	write_sctlr r0
	isb

	/* Early ARM secure MP specific configuration */
	bl	plat_cpu_reset_early

	ldr	r0, =_start
	write_vbar r0

#if defined(CFG_WITH_ARM_TRUSTED_FW)
	b	reset_primary
#else
	bl	get_core_pos
	cmp	r0, #0
	beq	reset_primary
	b	reset_secondary
#endif
UNWIND(	.fnend)
END_FUNC reset

	/*
	 * Setup sp to point to the top of the tmp stack for the current CPU:
	 * sp is assigned stack_tmp + (cpu_id + 1) * stack_tmp_stride
	 */
	.macro set_sp
		bl	get_core_pos
		cmp	r0, #CFG_TEE_CORE_NB_CORE
		/* Unsupported CPU, park it before it breaks something */
		bge	unhandled_cpu
		add	r0, r0, #1
		ldr	r2, =stack_tmp_stride
		ldr	r1, [r2]
		mul	r2, r0, r1
		ldr	r1, =stack_tmp
		add	sp, r1, r2
	.endm

LOCAL_FUNC reset_primary , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
#ifdef CFG_TEE_GDB_BOOT
	/* save linux boot args from GDB */
	ldr	r0, =gdb_bootargs
	stm	r0, {r6-r8}
#endif

#ifdef CFG_WITH_PAGER
	/*
	 * Move init code into correct location and move hashes to a
	 * temporary safe location until the heap is initialized.
	 *
	 * The binary is built as:
	 * [Pager code, rodata and data] : In correct location
	 * [Init code and rodata] : Should be copied to __text_init_start
	 * [Hashes] : Should be saved before initializing pager
	 *
	 */
	ldr	r0, =__text_init_start	/* dst */
	ldr	r1, =__data_end 	/* src */
	ldr	r2, =__tmp_hashes_end	/* dst limit */
	/* Copy backwards (as memmove) in case we're overlapping */
	sub	r2, r2, r0		/* len */
	add	r0, r0, r2
	add	r1, r1, r2
	ldr	r2, =__text_init_start
copy_init:
	ldmdb	r1!, {r3, r7-r13}
	stmdb	r0!, {r3, r7-r13}
	cmp	r0, r2
	bgt	copy_init
#endif

	set_sp

	/* complete ARM secure MP common configuration */
	bl	plat_cpu_reset_late

	/* Enable Console */
	bl	console_init

#ifdef CFG_PL310
	ldr	r0, =PL310_BASE
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
	ldr	r1, =__tmp_hashes_end
#else
	ldr	r1, =_end
#endif
	sub	r1, r1, #1
	bl	arm_cl1_d_invbyva

#ifdef CFG_PL310
	ldr	r0, =PL310_BASE
	ldr	r1, =__text_start
#ifdef CFG_WITH_PAGER
	ldr	r2, =__init_end
#else
	ldr	r2, =_end
#endif
	sub	r2, r2, #1
	bl	arm_cl2_invbypa

	ldr	r0, =PL310_BASE
	bl	arm_cl2_enable
#endif

	bl	core_init_mmu_map
	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	r0, r4		/* pageable part address */
	mov	r1, r5		/* ns-entry address */
	mov	r2, r6		/* DT address */
	bl	generic_boot_init_primary
	mov	r4, r0		/* save entry test vector */

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
	bl	pl310_base
	ldr	r1, =__text_start
#ifdef CFG_WITH_PAGER
	ldr	r2, =__init_end
#else
	ldr	r2, =_end
#endif
	sub	r2, r2, #1
	bl	arm_cl2_cleaninvbypa

#endif

#ifdef CFG_PL310_LOCKED
	bl	pl310_base
	bl	arm_cl2_lockallways
	bl	pl310_base
	bl	arm_cl2_invbyway
#endif

	bl	wait_secondary

	/*
	 * Clear current thread id now to allow the thread to be reused on
	 * next entry. Matches the thread_init_boot_thread() in
	 * generic_boot.c.
	 */
	bl 	thread_clr_boot_thread

#ifdef CFG_TEE_GDB_BOOT
	/* restore linux boot arguments */
	ldr	r4, =gdb_bootargs
	ldm	r4, {r1-r3}
#else
#if defined(CFG_WITH_ARM_TRUSTED_FW)
	/* Pass the vector address returned from main_init */
	mov	r0, r4
	mov	r1, r0
#else
	mov	r1, #0
	mov	r2, #0
	mov	r3, #0
#endif /*CFG_WITH_ARM_TRUSTED_FW*/
#endif /*CFG_TEE_GDB_BOOT*/

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC reset_primary


LOCAL_FUNC unhandled_cpu , :
UNWIND(	.fnstart)
	wfi
	b	unhandled_cpu
UNWIND(	.fnend)
END_FUNC unhandled_cpu

#if defined(CFG_WITH_ARM_TRUSTED_FW)
FUNC cpu_on_handler , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mov	r4, r0
	mov	r5, r1
	mov	r6, lr
	read_sctlr r0
	orr	r0, r0, #SCTLR_A
	write_sctlr r0

	ldr	r0, =_start
	write_vbar r0

	mov	r4, lr
	set_sp

	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	r0, r4
	mov	r1, r5
	bl	generic_boot_cpu_on_handler

	bx	r6
UNWIND(	.fnend)
END_FUNC cpu_on_handler

#else /* defined(CFG_WITH_ARM_TRUSTED_FW) */

LOCAL_FUNC reset_secondary , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	bl	wait_primary

	set_sp

	bl	plat_cpu_reset_late

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
UNWIND(	.fnend)
END_FUNC reset_secondary
#endif /* defined(CFG_WITH_ARM_TRUSTED_FW) */
