/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <kernel/unwind.h>
#include <platform_config.h>

/* Let platforms override this if needed */
.weak get_core_pos_mpidr

/* size_t __get_core_pos(void); */
FUNC __get_core_pos , :
UNWIND(	.fnstart)
	read_mpidr r0
	b get_core_pos_mpidr
UNWIND(	.fnend)
END_FUNC __get_core_pos

/* size_t get_core_pos_mpidr(uint32_t mpidr); */
FUNC get_core_pos_mpidr , :
UNWIND(	.fnstart)
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	and	r1, r0, #MPIDR_CPU_MASK
	and	r0, r0, #MPIDR_CLUSTER_MASK
	add	r0, r1, r0, LSR #(MPIDR_CLUSTER_SHIFT - CFG_CORE_CLUSTER_SHIFT)
	bx	lr
UNWIND(	.fnend)
END_FUNC get_core_pos_mpidr

/*
 * uint32_t temp_set_mode(int cpu_mode)
 *   returns cpsr to be set
 */
LOCAL_FUNC temp_set_mode , :
UNWIND(	.fnstart)
	mov	r1, r0
	cmp	r1, #CPSR_MODE_USR	/* update mode: usr -> sys */
	moveq	r1, #CPSR_MODE_SYS
	cpsid	aif			/* disable interrupts */
	mrs	r0, cpsr		/* get cpsr with disabled its*/
	bic	r0, #CPSR_MODE_MASK	/* clear mode */
	orr	r0, r1			/* set expected mode */
	bx	lr
UNWIND(	.fnend)
END_FUNC temp_set_mode

/* uint32_t read_mode_sp(int cpu_mode) */
FUNC read_mode_sp , :
UNWIND(	.fnstart)
	push	{r4, lr}
UNWIND(	.save	{r4, lr})
	mrs	r4, cpsr		/* save cpsr */
	bl	temp_set_mode
	msr	cpsr, r0		/* set the new mode */
	mov	r0, sp			/* get the function result */
	msr	cpsr, r4		/* back to the old mode */
	pop	{r4, pc}
UNWIND(	.fnend)
END_FUNC read_mode_sp

/* uint32_t read_mode_lr(int cpu_mode) */
FUNC read_mode_lr , :
UNWIND(	.fnstart)
	push	{r4, lr}
UNWIND(	.save	{r4, lr})
	mrs	r4, cpsr		/* save cpsr */
	bl	temp_set_mode
	msr	cpsr, r0		/* set the new mode */
	mov	r0, lr			/* get the function result */
	msr	cpsr, r4		/* back to the old mode */
	pop	{r4, pc}
UNWIND(	.fnend)
END_FUNC read_mode_lr
