/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <kernel/unwind.h>
#include <platform_config.h>


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
	mov	r3, r0

	/*
	 * Shift MPIDR value if it's not already shifted.
	 * Using logical shift ensures AFF0 to be filled with zeroes.
	 * This part is necessary even if CFG_CORE_THREAD_SHIFT is 0 because
	 * MT bit can be set on single threaded systems where all the AFF0
	 * values are zeroes.
	 */
	tst	r0, #MPIDR_MT_MASK
	lsleq	r3, r0, #MPIDR_AFFINITY_BITS

	/*
	 * At this point the MPIDR layout is always shifted so it looks
	 * as follows AFF2 -> cluster, AFF1 -> core, AFF0 -> thread
	 */
#if CFG_CORE_THREAD_SHIFT == 0
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	ubfx	r0, r3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	r1, r3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
	add	r0, r0, r1, LSL #(CFG_CORE_CLUSTER_SHIFT)
#else
	/*
	 * Calculate CorePos =
	 * ((ClusterId * (cores/cluster)) + CoreId) * (threads/core) + ThreadId
	 */
	ubfx	r0, r3, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	r1, r3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	r2, r3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
	add	r1, r1, r2, LSL #(CFG_CORE_CLUSTER_SHIFT)
	add	r0, r0, r1, LSL #(CFG_CORE_THREAD_SHIFT)
#endif

	bx	lr
UNWIND(	.fnend)
END_FUNC get_core_pos_mpidr

/* Let platforms override this if needed */
.weak get_core_pos_mpidr

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
