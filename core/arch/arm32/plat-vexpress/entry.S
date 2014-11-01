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
#include <arm32.h>
#include <arm32_macros.S>
#include <sm/teesmc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>

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

LOCAL_FUNC reset , :
	/*
	 * Enable alignment checks and disable data and instruction cache.
	 */
	read_sctlr r0
	orr	r0, r0, #SCTLR_A
	bic	r0, r0, #SCTLR_C
	bic	r0, r0, #SCTLR_I
	write_sctlr r0

	ldr	r0, =_start
	write_vbar r0

	mov	r4, lr
	bl	get_core_pos
	lsl	r0, #2
	cmp	r0, #CFG_TEE_CORE_NB_CORE
	/* Unsupported CPU, park it before it breaks something */
	bge	unhandled_cpu
	ldr	r1, =stack_tmp_top
	ldr	sp, [r1, r0]

#if 0
	bl	dcache_clean_inv
	bl	icache_inv
#endif
	bl	core_init_mmu
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	r0, r4
	bl	main_init

#if PLATFORM_FLAVOR == PLATFORM_FLAVOR_FVP
	/* Pass the vector address returned from main_init */
	mov     r1, r0
#elif PLATFORM_FLAVOR == PLATFORM_FLAVOR_QEMU
	mov	r1, #0
	mov	r2, #0
	mov	r3, #0
#endif
	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC reset

LOCAL_FUNC unhandled_cpu , :
	wfi
	b	unhandled_cpu
END_FUNC unhandled_cpu

#if PLATFORM_FLAVOR == PLATFORM_FLAVOR_FVP
FUNC cpu_on_handler , :
	mov	r4, r0
	mov	r5, r1
	mov	r6, lr
	read_sctlr r0
	orr	r0, r0, #SCTLR_A
	write_sctlr r0

	ldr	r0, =_start
	write_vbar r0

	mov	r4, lr
	bl	get_core_pos
	lsl	r0, #2
	ldr	r1, =stack_tmp_top
	ldr	sp, [r1, r0]

#if 0
	bl	dcache_clean_inv
	bl	icache_inv
#endif
	bl	core_init_mmu
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	r0, r4
	mov	r1, r5
	bl	main_cpu_on_handler
	bx	r6
END_FUNC cpu_on_handler
#endif
