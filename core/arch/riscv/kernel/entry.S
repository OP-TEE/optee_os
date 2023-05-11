/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <riscv.h>
#include <riscv_macros.S>

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
	la	a1, boot_mmu_config
	LDR	a0, CORE_MMU_CONFIG_SATP(a1)
	csrw	CSR_SATP, a0
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
.option push
.option norelax
	la	gp, __global_pointer$
.option pop
#ifdef CFG_RISCV_M_MODE
	csrr	a0, CSR_MHARTID
#endif
	csrw	CSR_XSCRATCH, a0
	bnez	a0, reset_secondary
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
	jal	boot_init_primary_late

	cpu_is_ready
	flush_cpu_semaphores
	wait_secondary

	jal	thread_clr_boot_thread
	j	mu_service
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
	j	.
END_FUNC reset_secondary

LOCAL_FUNC unhandled_cpu , :
	wfi
	j	unhandled_cpu
END_FUNC unhandled_cpu

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
