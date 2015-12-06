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
#include <kernel/unwind.h>

/* Let platforms override this if needed */
.weak get_core_pos

FUNC get_core_pos , :
UNWIND(	.fnstart)
	read_mpidr r0
	/* Calculate CorePos = (ClusterId * 4) + CoreId */
	and	r1, r0, #MPIDR_CPU_MASK
	and	r0, r0, #MPIDR_CLUSTER_MASK
	add	r0, r1, r0, LSR #6
	bx	lr
UNWIND(	.fnend)
END_FUNC get_core_pos

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
