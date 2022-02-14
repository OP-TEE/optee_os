/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <platform_config.h>
#include <riscv.h>

.section .data
.balign 4

#ifdef CFG_BOOT_SYNC_CPU
.equ SEM_CPU_READY, 1
#endif

	/*
	 * Setup sp to point to the top of the tmp stack for the current CPU:
	 * sp is assigned stack_tmp_export + cpu_id * stack_tmp_stride
	 */
.macro set_sp
	/* Unsupported CPU, park it before it breaks something */
	li	t1, CFG_TEE_CORE_NB_CORE
	csrr	t0, CSR_MHARTID
	bge	t0, t1, unhandled_cpu
	la	t2, stack_tmp_export
	lw	t1, stack_tmp_stride
	/*
	 * t0 is core pos
	 * t1 is value of stack_tmp_stride
	 * t2 is value of stack_tmp_export
	 */
	mv	sp, t2
	/* Don't use mul instruction because not all harts support it. */
	mv	a0, t0
	mv	a1, t1
	mv	a2, a0
	li	a0, 0
1:
	andi	a3, a1, 1
	beqz	a3, 2f
	add	a0, a0, a2
2:
	srli	a1, a1, 1
	slli	a2, a2, 1
	bnez	a1, 1b
	add	sp, sp, a0
.endm

.macro cpu_is_ready
#ifdef CFG_BOOT_SYNC_CPU
	csrr	t0, CSR_MHARTID
	la	t1, sem_cpu_sync
	slli	t0, t0, 2
	add	t1, t1, t0
	li	t2, SEM_CPU_READY
	sw	t2, 0(t1)
	fence
#endif
.endm

.macro set_tp
	li	a0, THREAD_CORE_LOCAL_SIZE
	csrr	a1, CSR_MHARTID
	la	tp, thread_core_local
	mv	a2, a0
	li	a0, 0
1:
	andi	a3, a1, 1
	beqz	a3, 2f
	add	a0, a0, a2
2:
	srli	a1, a1, 1
	slli	a2, a2, 1
	bnez	a1, 1b
	add	tp, tp, a0
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

.macro flush_cpu_semaphores
.endm

.macro bootargs_entry
	/*
	 * Save boot arguments
	 */
.endm

FUNC _start , :
	csrr	t0, CSR_MHARTID
	bnez	t0, reset_secondary
	jal	reset_primary
	j	.
END_FUNC _start

LOCAL_FUNC reset_primary , : , .identity_map
UNWIND(	.cantunwind)

	bootargs_entry

	/*
	 * Zero bss
	 */
1:
	lla	t0, __bss_start
	lla	t1, __bss_end
	beq	t0, t1, 1f
0:
	STR	zero, (t0)
	add	t0, t0, RISCV_XLEN_BYTES
	bne	t0, t1, 0b
1:

	csrw satp, 0
	set_sp
	set_tp

	jal thread_init_thread_core_local

	jal plat_primary_init_early
	jal console_init

	mv	a0, x0
	la	a1, boot_mmu_config
	jal	core_init_mmu_map

	jal boot_init_primary_early
	jal boot_init_primary_late

	cpu_is_ready
	flush_cpu_semaphores
	wait_secondary
	j	.
END_FUNC reset_primary

LOCAL_FUNC reset_secondary , : , .identity_map
UNWIND(	.cantunwind)
	wait_primary
	set_sp
	set_tp
	cpu_is_ready

	jal boot_init_secondary
	j	.
END_FUNC reset_secondary
DECLARE_KEEP_PAGER reset_secondary

LOCAL_FUNC unhandled_cpu , :
	wfi
END_FUNC unhandled_cpu

#ifdef CFG_BOOT_SYNC_CPU
LOCAL_DATA sem_cpu_sync_start , :
	.word	sem_cpu_sync
END_DATA sem_cpu_sync_start

LOCAL_DATA sem_cpu_sync_end , :
	.word	sem_cpu_sync + (CFG_TEE_CORE_NB_CORE << 2)
END_DATA sem_cpu_sync_end
#endif

LOCAL_DATA stack_tmp_export_rel , :
	.word	stack_tmp_export - stack_tmp_export_rel
END_DATA stack_tmp_export_rel

LOCAL_DATA stack_tmp_stride_rel , :
	.word	stack_tmp_stride - stack_tmp_stride_rel
END_DATA stack_tmp_stride_rel

	.balign	8
LOCAL_DATA boot_mmu_config , : /* struct core_mmu_config */
	.skip	CORE_MMU_CONFIG_SIZE
END_DATA boot_mmu_config
