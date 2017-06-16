/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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

.section .text.boot
.align	5
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

LOCAL_FUNC reset , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
        read_sctlr  r0
#if defined(CFG_SCTLR_ALIGNMENT_CHECK)
	orr	r0, r0, #SCTLR_A
#else
	bic	r0, r0, #SCTLR_A
#endif
	write_sctlr r0

	ldr	   r0, =_start
	write_vbar r0
	
	mov	r4, r1
	bl	get_core_pos
	ldr	r1, =stack_tmp_stride
	ldr	r1, [r1]
	mul	r1, r0, r1
	ldr	r0, =stack_tmp_export
	ldr	r0, [r0]
	add	sp, r1, r0

    	/* NSACR configuration */
    	read_nsacr  r1
	orr     r1, r1, #NSACR_CP10
	orr     r1, r1, #NSACR_CP11
	orr     r1, r1, #NSACR_NS_SMP
    	write_nsacr r1

	/* Enable SMP bit */
	read_actlr  r0
	orr     r0, r0, #ACTLR_SMP
	write_actlr  r0

	/* init BSS section */
	ldr	r0, =__bss_start
	ldr	r2, =__bss_end
	sub	r2, r2, r0
	ldr	r1, =0
	bl	memset

	bl	core_init_mmu_map
	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache
	
	/* r4: the return address of normal world */
	mov	r0, r4
	bl	main_init

	mov	r1, #0
	mov	r2, #0
	mov	r3, #0
	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should never return */
UNWIND(	.fnend)
END_FUNC reset

