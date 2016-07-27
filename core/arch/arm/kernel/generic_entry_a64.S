/*
 * Copyright (c) 2015, Linaro Limited
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
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>

	/*
	 * Setup SP_EL0 and SPEL1, SP will be set to SP_EL0.
	 * SP_EL0 is assigned stack_tmp + (cpu_id + 1) * stack_tmp_stride
	 * SP_EL1 is assigned thread_core_local[cpu_id]
	 */
	.macro set_sp
		bl	get_core_pos
		cmp	x0, #CFG_TEE_CORE_NB_CORE
		/* Unsupported CPU, park it before it breaks something */
		bge	unhandled_cpu
		add	x0, x0, #1
		adr	x2, stack_tmp_stride
		ldr	w1, [x2]
		mul	x2, x0, x1
		adrp	x1, stack_tmp
		add	x1, x1, :lo12:stack_tmp
		add	x1, x1, x2
		msr	spsel, #0
		mov	sp, x1
		bl	thread_get_core_local
		msr	spsel, #1
		mov	sp, x0
		msr	spsel, #0
	.endm

.section .text.boot
FUNC _start , :
	mov	x19, x0		/* Save pagable part address */
	mov	x20, x2		/* Save DT address */

	adr	x0, reset_vect_table
	msr	vbar_el1, x0
	isb

	mrs	x0, sctlr_el1
	mov	x1, #(SCTLR_I | SCTLR_A | SCTLR_SA)
	orr	x0, x0, x1
	msr	sctlr_el1, x0
	isb

#ifdef CFG_WITH_PAGER
	/*
	 * Move init code into correct location
	 *
	 * The binary is built as:
	 * [Pager code, rodata and data] : In correct location
	 * [Init code and rodata] : Should be copied to __text_init_start
	 * [Hashes] : Should be saved before clearing bss
	 *
	 * When we copy init code and rodata into correct location we don't
	 * need to worry about hashes being overwritten as size of .bss,
	 * .heap, .nozi and .heap3 is much larger than the size of init
	 * code and rodata and hashes.
	 */
	adr	x0, __text_init_start	/* dst */
	adr	x1, __data_end 	/* src */
	adr	x2, __rodata_init_end	/* dst limit */
copy_init:
	ldp	x3, x4, [x1], #16
	stp	x3, x4, [x0], #16
	cmp	x0, x2
	b.lt	copy_init
#endif

	/* Setup SP_EL0 and SP_EL1, SP will be set to SP_EL0 */
	set_sp

	/* Enable aborts now that we can receive exceptions */
	msr	daifclr, #DAIFBIT_ABT

	adr	x0, __text_start
#ifdef CFG_WITH_PAGER
	adrp	x1, __init_end
	add	x1, x1, :lo12:__init_end
#else
	adrp	x1, _end
	add	x1, x1, :lo12:_end
#endif
	sub	x1, x1, x0
	bl	inv_dcache_range

	/* Enable Console */
	bl	console_init

	bl	core_init_mmu_map
	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	x0, x19		/* pagable part address */
	mov	x1, #-1
	mov	x2, x20		/* DT address */
	bl	generic_boot_init_primary

	/*
	 * In case we've touched memory that secondary CPUs will use before
	 * they have turned on their D-cache, clean and invalidate the
	 * D-cache before exiting to normal world.
	 */
	mov	x19, x0
	adr	x0, __text_start
#ifdef CFG_WITH_PAGER
	adrp	x1, __init_end
	add	x1, x1, :lo12:__init_end
#else
	adrp	x1, _end
	add	x1, x1, :lo12:_end
#endif
	sub	x1, x1, x0
	bl	flush_dcache_range


	/*
	 * Clear current thread id now to allow the thread to be reused on
	 * next entry. Matches the thread_init_boot_thread in
	 * generic_boot.c.
	 */
	bl 	thread_clr_boot_thread

	/* Pass the vector address returned from main_init */
	mov	x1, x19
	mov	x0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC _start


.section .text.cpu_on_handler
FUNC cpu_on_handler , :
	mov	x19, x0
	mov	x20, x1
	mov	x21, x30

	adr	x0, reset_vect_table
	msr	vbar_el1, x0
	isb

	mrs	x0, sctlr_el1
	mov	x1, #(SCTLR_I | SCTLR_A | SCTLR_SA)
	orr	x0, x0, x1
	msr	sctlr_el1, x0
	isb

	/* Setup SP_EL0 and SP_EL1, SP will be set to SP_EL0 */
	set_sp

	/* Enable aborts now that we can receive exceptions */
	msr	daifclr, #DAIFBIT_ABT

	bl	core_init_mmu_regs
	bl	cpu_mmu_enable
	bl	cpu_mmu_enable_icache
	bl	cpu_mmu_enable_dcache

	mov	x0, x19
	mov	x1, x20
	mov	x30, x21
	b	generic_boot_cpu_on_handler
END_FUNC cpu_on_handler

LOCAL_FUNC unhandled_cpu , :
	wfi
	b	unhandled_cpu
END_FUNC unhandled_cpu

	/*
	 * This macro verifies that the a given vector doesn't exceed the
	 * architectural limit of 32 instructions. This is meant to be placed
	 * immedately after the last instruction in the vector. It takes the
	 * vector entry as the parameter
	 */
	.macro check_vector_size since
	  .if (. - \since) > (32 * 4)
	    .error "Vector exceeds 32 instructions"
	  .endif
	.endm

	.align	7
LOCAL_FUNC reset_vect_table , :
	/* -----------------------------------------------------
	 * Current EL with SP0 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
SynchronousExceptionSP0:
	b	SynchronousExceptionSP0
	check_vector_size SynchronousExceptionSP0

	.align	7
IrqSP0:
	b	IrqSP0
	check_vector_size IrqSP0

	.align	7
FiqSP0:
	b	FiqSP0
	check_vector_size FiqSP0

	.align	7
SErrorSP0:
	b	SErrorSP0
	check_vector_size SErrorSP0

	/* -----------------------------------------------------
	 * Current EL with SPx: 0x200 - 0x380
	 * -----------------------------------------------------
	 */
	.align	7
SynchronousExceptionSPx:
	b	SynchronousExceptionSPx
	check_vector_size SynchronousExceptionSPx

	.align	7
IrqSPx:
	b	IrqSPx
	check_vector_size IrqSPx

	.align	7
FiqSPx:
	b	FiqSPx
	check_vector_size FiqSPx

	.align	7
SErrorSPx:
	b	SErrorSPx
	check_vector_size SErrorSPx

	/* -----------------------------------------------------
	 * Lower EL using AArch64 : 0x400 - 0x580
	 * -----------------------------------------------------
	 */
	.align	7
SynchronousExceptionA64:
	b	SynchronousExceptionA64
	check_vector_size SynchronousExceptionA64

	.align	7
IrqA64:
	b	IrqA64
	check_vector_size IrqA64

	.align	7
FiqA64:
	b	FiqA64
	check_vector_size FiqA64

	.align	7
SErrorA64:
	b   	SErrorA64
	check_vector_size SErrorA64

	/* -----------------------------------------------------
	 * Lower EL using AArch32 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7
SynchronousExceptionA32:
	b	SynchronousExceptionA32
	check_vector_size SynchronousExceptionA32

	.align	7
IrqA32:
	b	IrqA32
	check_vector_size IrqA32

	.align	7
FiqA32:
	b	FiqA32
	check_vector_size FiqA32

	.align	7
SErrorA32:
	b	SErrorA32
	check_vector_size SErrorA32

END_FUNC reset_vect_table
