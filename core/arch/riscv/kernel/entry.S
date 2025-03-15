/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/thread_private_arch.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <riscv.h>
#include <riscv_macros.S>
#include <tee/optee_abi.h>
#include <tee/teeabi_opteed.h>
#include <tee/teeabi_opteed_macros.h>

.section .data
.balign 4

#ifdef CFG_BOOT_SYNC_CPU
.equ SEM_CPU_READY, 1
#endif

	/*
	 * Setup sp to point to the top of the tmp stack for the current CPU:
	 * sp is assigned:
	 * stack_tmp + (hart_index + 1) * stack_tmp_stride - STACK_TMP_GUARD
	 */
.macro set_sp
	/* Unsupported CPU, park it before it breaks something */
	li	t1, CFG_TEE_CORE_NB_CORE
	csrr	t0, CSR_XSCRATCH /* t0: hart_index */
	bge	t0, t1, unhandled_cpu
	addi	t0, t0, 1
	lw	t1, stack_tmp_stride
	mul	t1, t0, t1
	la	t2, stack_tmp_rel
	lw	t0, 0(t2)
	add	t0, t0, t2
	add	sp, t1, t0
.endm

.macro cpu_is_ready
#ifdef CFG_BOOT_SYNC_CPU
	csrr	t0, CSR_XSCRATCH
	la	t1, sem_cpu_sync
	slli	t0, t0, 2
	add	t1, t1, t0
	li	t2, SEM_CPU_READY
	sw	t2, 0(t1)
	fence
#endif
.endm

.macro set_tp
	csrr	a3, CSR_XSCRATCH /* a3: hart_index */
	li	a1, THREAD_CORE_LOCAL_SIZE
	la	tp, thread_core_local
	LDR	tp, 0(tp)
	mul	a2, a1, a3
	add	tp, tp, a2
	sw	a0, THREAD_CORE_LOCAL_HART_ID(tp)
	sw	a3, THREAD_CORE_LOCAL_HART_INDEX(tp)
.endm

.macro set_satp
	/*
	 * a0 = hart_index
	 * a1 = address of boot_mmu_config.satp[0]
	 * a2 = size of CSR SATP
	 *
	 * This hart's SATP is of value (a1 + (a0 * a2)).
	 */
	csrr	a0, CSR_XSCRATCH
	la	a1, boot_mmu_config
	addi	a1, a1, CORE_MMU_CONFIG_SATP
	li	a2, CORE_MMU_CONFIG_SATP_SIZE
	mul	a0, a0, a2
	add	a1, a1, a0
	LDR	a2, 0(a1)
	csrw	CSR_SATP, a2
	sfence.vma	zero, zero
.endm

.macro wait_primary
#ifdef CFG_BOOT_SYNC_CPU
	la	t0, sem_cpu_sync
	li	t2, SEM_CPU_READY
1:
	fence	w, w
	lw	t1, 0(t0)
	bne	t1, t2, 1b
#endif
.endm

.macro wait_secondary
#ifdef CFG_BOOT_SYNC_CPU
	la	t0, sem_cpu_sync
	li	t1, CFG_TEE_CORE_NB_CORE
	li	t2, SEM_CPU_READY
1:
	addi	t1, t1, -1
	beqz	t1, 3f
	addi	t0, t0, 4
2:
	fence
	lw	t1, 0(t0)
	bne	t1, t2, 2b
	j	1b
3:
#endif
.endm

#ifdef CFG_BOOT_SYNC_CPU
#define flush_cpu_semaphores \
		la	t0, sem_cpu_sync_start
		la	t1, sem_cpu_sync_end
		fence
#else
#define flush_cpu_semaphores
#endif

FUNC _start , :
	/*
	 * Register usage:
	 * a0	- if non-NULL holds the hart ID
	 * a1	- if non-NULL holds the system DTB address
	 *
	 * s1 - saved a1
	 */
.option push
.option norelax
	la	gp, __global_pointer$
.option pop
#ifdef CFG_RISCV_M_MODE
	csrr	a0, CSR_MHARTID
#endif

#if defined(CFG_DT_ADDR)
	li	s1, CFG_DT_ADDR
#else
	mv	s1, a1		/* Save device tree address into s1 */
#endif
	/* Only first hart who wins lottery runs the primary boot sequence. */
	la	a3, hart_lottery
	li	a2, 1
	amoadd.w a3, a2, (a3)
	/* a3 read from hart_lottery also represents the hart_index */
	csrw	CSR_XSCRATCH, a3

	bnez	a3, reset_secondary
	jal	reset_primary
	j	.
END_FUNC _start

LOCAL_FUNC reset_primary , : , .identity_map
UNWIND(	.cantunwind)
	/*
	 * Zero bss
	 */
	lla	t0, __bss_start
	lla	t1, __bss_end
	beq	t0, t1, 1f
0:
	STR	zero, (t0)
	add	t0, t0, RISCV_XLEN_BYTES
	bne	t0, t1, 0b
1:
#ifdef CFG_RISCV_S_MODE
	lla	t0, _start
	lla	t1, start_addr
	STR	t0, (t1)
#endif

	csrw	CSR_SATP, zero

	/* Setup sp and tp */
#if defined(CFG_DYN_CONFIG)
	/*
	 * Point sp to a temporary stack at the end of mapped core memory.
	 * Point tp to a temporary struct thread_core_local before the temporary
	 * stack.
	 */
	la	t0, __vcore_free_end
	li	t1, THREAD_BOOT_INIT_TMP_ALLOC
	sub	t1, t0, t1

	/* Clear the allocated struct thread_core_local */
	add	t2, t1, THREAD_CORE_LOCAL_SIZE
1:	addi	t2, t2, -RISCV_XLEN_BYTES
	STR	zero, (t2)
	bgt	t2, t1, 1b

	li	t2, THREAD_ID_INVALID
	sh	t2, THREAD_CORE_LOCAL_CURR_THREAD(t1)
	li	t2, THREAD_CLF_TMP
	sw	t2, THREAD_CORE_LOCAL_FLAGS(t1)
	li	t2, (__STACK_CANARY_SIZE / 2)
	sub	t0, t0, t2
	STR	t0, THREAD_CORE_LOCAL_TMP_STACK_VA_END(t1)
	li	t2, (THREAD_BOOT_INIT_TMP_ALLOC / 2)
	sub	t2, t0, t2
	STR	t2, THREAD_CORE_LOCAL_ABT_STACK_VA_END(t1)
	csrr	t2, CSR_XSCRATCH /* t2: hart_index */
	sw	a0, THREAD_CORE_LOCAL_HART_ID(t1)
	sw	t2, THREAD_CORE_LOCAL_HART_INDEX(t1)

	mv	sp, t0
	mv	tp, t1
	/*
	 * Record a single core, to be changed later before secure world
	 * boot is done.
	 */
	la	t2, thread_core_local
	STR	tp, 0(t2)
	la	t2, thread_core_count
	li	t0, 1
	STR	t0, 0(t2)
#else
	set_sp
	set_tp

	/* Initialize thread_core_local[hart_index] for early boot */
	jal	thread_get_abt_stack
	mv	a1, sp
	STR	a1, THREAD_CORE_LOCAL_TMP_STACK_VA_END(tp)
	STR	a0, THREAD_CORE_LOCAL_ABT_STACK_VA_END(tp)
	li	a0, THREAD_ID_INVALID
	sh	a0, THREAD_CORE_LOCAL_CURR_THREAD(tp)
	li	a0, THREAD_CLF_TMP
	sw	a0, THREAD_CORE_LOCAL_FLAGS(tp)
#endif

	jal	plat_primary_init_early
	jal	console_init

	la	a0, __vcore_free_start
	la	a1, __vcore_free_end
#ifdef CFG_DYN_CONFIG
	li	a2, THREAD_BOOT_INIT_TMP_ALLOC
	sub	a1, a1, a2
#endif
	la	a2, __vcore_free_end
	jal	boot_mem_init

	mv	a0, x0
	la	a1, boot_mmu_config
	jal	core_init_mmu_map

	set_satp

#ifdef CFG_CORE_ASLR
#if defined(CFG_DYN_CONFIG)
	/*
	 * thread_core_local holds only one core and thread_core_count is 1
	 * so tp points to the updated pointer for thread_core_local.
	 */
	la	t0, thread_core_local
	STR	tp, 0(t0)
#endif
#endif

	jal	boot_init_primary_early

	mv	a0, s1		/* s1 contains saved device tree address */
	mv	a1, x0		/* unused */
	jal	boot_init_primary_late

#if defined(CFG_DYN_CONFIG)
	/* Get hart index */
	jal	__get_core_pos

	/*
	 * Switch to the new thread_core_local and thread_core_count and
	 * keep the pointer to the new thread_core_local in a1.
	 */
	LDR	a1, __thread_core_count_new
	la	a2, thread_core_count
	STR	a1, 0(a2)
	LDR	a1, __thread_core_local_new
	la	a2, thread_core_local
	STR	a1, 0(a2)

	/*
	 * Update tp to point the new thread_core_local.
	 * Update sp to use the new tmp stack.
	 */
	li	a2, THREAD_CORE_LOCAL_SIZE
	/* tp = a2 * a0(hart index) + a1(thread_core_local) */
	mul	a2, a2, a0
	add	tp, a2, a1
	LDR	sp, THREAD_CORE_LOCAL_TMP_STACK_VA_END(tp)
#endif

	/*
	 * Before entering boot_init_primary_runtime(), we do these two steps:
	 * 1. Save current sp to s2, and set sp as threads[0].stack_va_end
	 * 2. Clear the flag which indicates usage of the temporary stack in the
	 *    current hart's thread_core_local structure.
	 */
	mv	s2, sp
	la	a0, threads
	LDR	a0, 0(a0)
	LDR	a0, THREAD_CTX_STACK_VA_END(a0)
	mv	sp, a0
	jal	thread_get_core_local
	mv	s3, a0
	sw	zero, THREAD_CORE_LOCAL_FLAGS(s3)

	jal	boot_init_primary_runtime
	jal	boot_init_primary_final

	/*
	 * After returning from boot_init_primary_late(), the flag and sp are
	 * restored.
	 */
	li	a0, THREAD_CLF_TMP
	sw	a0, THREAD_CORE_LOCAL_FLAGS(s3)
	mv	sp, s2

#ifdef _CFG_CORE_STACK_PROTECTOR
	/* Update stack canary value */
	addi	sp, sp, -STACK_ALIGNMENT
	mv	a0, sp
	li	a1, 1
#ifdef RV32
	li	a2, 4
#else
	li	a2, 8
#endif
	jal	plat_get_random_stack_canaries
	LDR	s0, 0(sp)
	la	s1, __stack_chk_guard
	STR	s0, 0(s1)
	addi	sp, sp, STACK_ALIGNMENT
#endif

	cpu_is_ready
	flush_cpu_semaphores
	wait_secondary

	jal	thread_clr_boot_thread

	li	a0, TEEABI_OPTEED_RETURN_ENTRY_DONE
	la	a1, thread_vector_table
	li	a2, 0
	li	a3, 0
	li	a4, 0
	li	a5, 0
	j	thread_return_to_udomain
END_FUNC reset_primary

LOCAL_FUNC reset_secondary , : , .identity_map
UNWIND(	.cantunwind)
	wait_primary
	csrw	CSR_SATP, zero
#if defined(CFG_DYN_CONFIG)
	/*
	 * Update tp to point the new thread_core_local.
	 * Update sp to use the new tmp stack.
	 */
	csrr	t0, CSR_XSCRATCH /* t0: hart_index */
	LDR	t1, thread_core_local
	li	t2, THREAD_CORE_LOCAL_SIZE
	/* tp = t2 * t0(hart index) + t1(thread_core_local) */
	mul	t2, t2, t0
	add	tp, t2, t1
	sw	a0, THREAD_CORE_LOCAL_HART_ID(tp)
	sw	t0, THREAD_CORE_LOCAL_HART_INDEX(tp)
	LDR	sp, THREAD_CORE_LOCAL_TMP_STACK_VA_END(tp)
#else
	set_sp
	set_tp
#endif
	set_satp
	cpu_is_ready

	jal	boot_init_secondary
#ifdef CFG_RISCV_WITH_M_MODE_SM
	/* Return to untrusted domain */
	li	a0, TEEABI_OPTEED_RETURN_ON_DONE
	li	a1, 0
	li	a2, 0
	li	a3, 0
	li	a4, 0
	li	a5, 0
	j	thread_return_to_udomain
#endif
	j	.
END_FUNC reset_secondary

LOCAL_FUNC unhandled_cpu , :
	wfi
	j	unhandled_cpu
END_FUNC unhandled_cpu

	.section .identity_map.data
	.balign	8
LOCAL_DATA hart_lottery , :
	/* The hart who first increments this variable will be primary hart. */
	.word	0
END_DATA hart_lottery

#ifdef CFG_BOOT_SYNC_CPU
LOCAL_DATA sem_cpu_sync_start , :
	.word	sem_cpu_sync
END_DATA sem_cpu_sync_start

LOCAL_DATA sem_cpu_sync_end , :
	.word	sem_cpu_sync + (CFG_TEE_CORE_NB_CORE << 2)
END_DATA sem_cpu_sync_end
#endif

#if !defined(CFG_DYN_CONFIG)
LOCAL_DATA stack_tmp_rel , :
	.word	stack_tmp - stack_tmp_rel - STACK_TMP_GUARD
END_DATA stack_tmp_rel
#endif

	.section .identity_map.data
	.balign	8
DATA boot_mmu_config , : /* struct core_mmu_config */
	.skip	CORE_MMU_CONFIG_SIZE
END_DATA boot_mmu_config
