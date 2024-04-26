/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread_private.h>
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
	 * stack_tmp + (hartid + 1) * stack_tmp_stride - STACK_TMP_GUARD
	 */
.macro set_sp
	/* Unsupported CPU, park it before it breaks something */
	li	t1, CFG_TEE_CORE_NB_CORE
	csrr	t0, CSR_XSCRATCH
	bge	t0, t1, unhandled_cpu
	addi	t0, t0, 1
	lw	t1, stack_tmp_stride
	/*
	 * t0 = (hartid + 1)
	 * t1 = value of stack_tmp_stride
	 * value of stack_tmp_rel = stack_tmp - stack_tmp_rel - STACK_TMP_GUARD
	 * sp = stack_tmp + (hartid + 1) * stack_tmp_stride - STACK_TMP_GUARD
	 *    = stack_tmp_rel + (value of stack_tmp_rel) + (t0 * t1)
	 */
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
	csrr	a0, CSR_XSCRATCH
	li	a1, THREAD_CORE_LOCAL_SIZE
	la	tp, thread_core_local
	mul	a2, a1, a0
	add	tp, tp, a2
	sw	a0, THREAD_CORE_LOCAL_HART_ID(tp)
.endm

.macro set_satp
	/*
	 * a0 = hartid
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

.macro bootargs_entry
	/*
	 * Save boot arguments
	 */
	la	t0, boot_args
	/* Save boot hart */
	STR	a0, REGOFF(0)(t0)
	/* Save FDT address */
	STR	a1, REGOFF(1)(t0)
.endm

FUNC _start , :
	/*
	 * Register usage:
	 * a0	- if non-NULL holds the hart ID
	 * a1	- if non-NULL holds the system DTB address
	 *
	 * CSR_XSCRATCH - saved a0
	 * s1 - saved a1
	 */
.option push
.option norelax
	la	gp, __global_pointer$
.option pop
#ifdef CFG_RISCV_M_MODE
	csrr	a0, CSR_MHARTID
#endif
	csrw	CSR_XSCRATCH, a0
#if defined(CFG_DT_ADDR)
	li	s1, CFG_DT_ADDR
#else
	mv	s1, a1		/* Save device tree address into s1 */
#endif

	/* Only first hart who wins lottery runs the primary boot sequence. */
	la	a3, hart_lottery
	li	a2, 1
	amoadd.w a3, a2, (a3)
	bnez	a3, reset_secondary
	jal	reset_primary
	j	.
END_FUNC _start

LOCAL_FUNC reset_primary , : , .identity_map
UNWIND(	.cantunwind)

	bootargs_entry

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
	set_sp
	set_tp

	jal	thread_init_thread_core_local
	jal	plat_primary_init_early
	jal	console_init

	mv	a0, x0
	la	a1, boot_mmu_config
	jal	core_init_mmu_map

	set_satp

	jal	boot_init_primary_early

	/*
	 * Before entering boot_init_primary_late(), we do these two steps:
	 * 1. Save current sp to s2, and set sp as threads[0].stack_va_end
	 * 2. Clear the flag which indicates usage of the temporary stack in the
	 *    current hart's thread_core_local structure.
	 */
	mv	s2, sp
	la	a0, threads
	LDR	a0, THREAD_CTX_STACK_VA_END(a0)
	mv	sp, a0
	jal	thread_get_core_local
	mv	s3, a0
	sw	zero, THREAD_CORE_LOCAL_FLAGS(s3)

	mv	a0, s1		/* s1 contains saved device tree address */
	mv	a1, x0		/* unused */
	jal	boot_init_primary_late

	/*
	 * After returning from boot_init_primary_late(), the flag and sp are
	 * restored.
	 */
	li	a0, THREAD_CLF_TMP
	sw	a0, THREAD_CORE_LOCAL_FLAGS(s3)
	mv	sp, s2

	cpu_is_ready
	flush_cpu_semaphores
	wait_secondary

	jal	thread_clr_boot_thread

	li	a0, TEEABI_OPTEED_RETURN_ENTRY_DONE
	la	a1, thread_vector_table
	j	thread_return_to_udomain
END_FUNC reset_primary

LOCAL_FUNC reset_secondary , : , .identity_map
UNWIND(	.cantunwind)
	wait_primary
	csrw	CSR_SATP, zero
	set_sp
	set_tp
	set_satp
	cpu_is_ready

	jal	boot_init_secondary
#ifdef CFG_RISCV_WITH_M_MODE_SM
	/* Return to untrusted domain */
	li	a0, TEEABI_OPTEED_RETURN_ON_DONE
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

LOCAL_DATA stack_tmp_rel , :
	.word	stack_tmp - stack_tmp_rel - STACK_TMP_GUARD
END_DATA stack_tmp_rel

LOCAL_DATA stack_tmp_stride_rel , :
	.word	stack_tmp_stride - stack_tmp_stride_rel
END_DATA stack_tmp_stride_rel

	.balign	8
LOCAL_DATA boot_mmu_config , : /* struct core_mmu_config */
	.skip	CORE_MMU_CONFIG_SIZE
END_DATA boot_mmu_config
