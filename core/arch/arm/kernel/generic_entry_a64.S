/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <platform_config.h>

#include <arm64_macros.S>
#include <arm.h>
#include <asm.S>
#include <keep.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

	/*
	 * Setup SP_EL0 and SPEL1, SP will be set to SP_EL0.
	 * SP_EL0 is assigned stack_tmp_export + cpu_id * stack_tmp_stride
	 * SP_EL1 is assigned thread_core_local[cpu_id]
	 */
	.macro set_sp
		bl	__get_core_pos
		cmp	x0, #CFG_TEE_CORE_NB_CORE
		/* Unsupported CPU, park it before it breaks something */
		bge	unhandled_cpu
		adr	x1, stack_tmp_stride
		ldr	w1, [x1]
		mul	x1, x0, x1
		adrp	x0, stack_tmp_export
		add	x0, x0, :lo12:stack_tmp_export
		ldr	x0, [x0]
		msr	spsel, #0
		add	sp, x1, x0
		bl	thread_get_core_local
		msr	spsel, #1
		mov	sp, x0
		msr	spsel, #0
	.endm

	.macro set_sctlr_el1
		mrs	x0, sctlr_el1
		orr	x0, x0, #SCTLR_I
		orr	x0, x0, #SCTLR_SA
#if defined(CFG_CORE_RWDATA_NOEXEC)
		orr	x0, x0, #SCTLR_WXN
#endif
#if defined(CFG_SCTLR_ALIGNMENT_CHECK)
		orr	x0, x0, #SCTLR_A
#else
		bic	x0, x0, #SCTLR_A
#endif
		msr	sctlr_el1, x0
	.endm

FUNC _start , :
	mov	x19, x0		/* Save pagable part address */
	mov	x20, x2		/* Save DT address */

	adr	x0, reset_vect_table
	msr	vbar_el1, x0
	isb

	set_sctlr_el1
	isb

#ifdef CFG_WITH_PAGER
	/*
	 * Move init code into correct location and move hashes to a
	 * temporary safe location until the heap is initialized.
	 *
	 * The binary is built as:
	 * [Pager code, rodata and data] : In correct location
	 * [Init code and rodata] : Should be copied to __init_start
	 * [Hashes] : Should be saved before initializing pager
	 *
	 */
	adr	x0, __init_start	/* dst */
	adr	x1, __data_end		/* src */
	adr	x2, __tmp_hashes_end	/* dst limit */
	/* Copy backwards (as memmove) in case we're overlapping */
	sub	x2, x2, x0		/* len */
	add	x0, x0, x2		/* __init_start + len = __init_end */
	add	x1, x1, x2		/* __data_end + len */
	adr	x2, __init_start
copy_init:
	ldp	x3, x4, [x1, #-16]!
	stp	x3, x4, [x0, #-16]!
	cmp	x0, x2
	b.gt	copy_init
#endif

	/*
	 * Clear .bss, this code obviously depends on the linker keeping
	 * start/end of .bss at least 8 byte aligned.
	 */
	adr_l	x0, __bss_start
	adr_l	x1, __bss_end
clear_bss:
	str	xzr, [x0], #8
	cmp	x0, x1
	b.lt	clear_bss

#ifdef CFG_VIRTUALIZATION
	/*
	 * Clear .nex_bss, this code obviously depends on the linker keeping
	 * start/end of .bss at least 8 byte aligned.
	 */
	adr	x0, __nex_bss_start
	adr	x1, __nex_bss_end
clear_nex_bss:
	str	xzr, [x0], #8
	cmp	x0, x1
	b.lt	clear_nex_bss
#endif

	/* Setup SP_EL0 and SP_EL1, SP will be set to SP_EL0 */
	set_sp

	/* Enable aborts now that we can receive exceptions */
	msr	daifclr, #DAIFBIT_ABT

	adr_l	x0, __text_start
#ifdef CFG_WITH_PAGER
	adrp	x1, __tmp_hashes_end
	add	x1, x1, :lo12:__tmp_hashes_end
#else
	adrp	x1, __end
	add	x1, x1, :lo12:__end
#endif
	sub	x1, x1, x0
	bl	dcache_inv_range

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
	adr_l	x0, __text_start
#ifdef CFG_WITH_PAGER
	adrp	x1, __tmp_hashes_end
	add	x1, x1, :lo12:__tmp_hashes_end
#else
	adrp	x1, __end
	add	x1, x1, :lo12:__end
#endif
	sub	x1, x1, x0
	bl	dcache_cleaninv_range


	/*
	 * Clear current thread id now to allow the thread to be reused on
	 * next entry. Matches the thread_init_boot_thread in
	 * generic_boot.c.
	 */
#ifndef CFG_VIRTUALIZATION
	bl 	thread_clr_boot_thread
#endif

	/* Pass the vector address returned from main_init */
	mov	x1, x19
	mov	x0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC _start
KEEP_INIT _start


FUNC cpu_on_handler , :
	mov	x19, x0
	mov	x20, x1
	mov	x21, x30

	adr	x0, reset_vect_table
	msr	vbar_el1, x0
	isb

	set_sctlr_el1
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
KEEP_PAGER cpu_on_handler

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

	.section .text.reset_vect_table
	.align	11
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
