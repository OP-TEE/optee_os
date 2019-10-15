/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <platform_config.h>

#include <arm64_macros.S>
#include <arm.h>
#include <asm.S>
#include <elf_common.h>
#include <generated/asm-defines.h>
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
#if defined(CFG_DT_ADDR)
	ldr     x20, =CFG_DT_ADDR
#else
	mov	x20, x2		/* Save DT address */
#endif

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

#ifdef CFG_CORE_ASLR
	/*
	 * The code is supposed to be linked against the address where
	 * binary was loaded (0 load offset). However, since AArch64 uses
	 * relocations of the new Rela type, relocations has to be
	 * processed to guarantee that all updated locations holds the
	 * correct value.
	 *
	 * N.b, it seems that some toolchains already provides expected
	 * values at the target locations.
	 */
	mov	x0, #0
	bl	relocate
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

#ifdef CFG_CORE_ASLR
	mov	x0, x20
	bl	get_aslr_seed
#else
	mov	x0, #0
#endif

	adr	x1, boot_mmu_config
	bl	core_init_mmu_map

#ifdef CFG_CORE_ASLR
	/*
	 * Process relocation information again updating for the new
	 * offset. We're doing this now before MMU is enabled as some of
	 * the memory will become write protected.
	 */
	ldr	x0, boot_mmu_config + CORE_MMU_CONFIG_LOAD_OFFSET
	bl	relocate
#endif

	bl	__get_core_pos
	bl	enable_mmu
#ifdef CFG_CORE_ASLR
	/*
	 * Reinitialize console, since register_serial_console() has
	 * previously registered a PA and with ASLR the VA is different
	 * from the PA.
	 */
	bl	console_init
#endif

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

	/*
	 * Pass the vector address returned from main_init
	 * Compensate for the load offset since cpu_on_handler() is
	 * called with MMU off.
	 */
	ldr	x0, boot_mmu_config + CORE_MMU_CONFIG_LOAD_OFFSET
	sub	x1, x19, x0
	mov	x0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC _start
KEEP_INIT _start

#ifdef CFG_CORE_ASLR
LOCAL_FUNC relocate , :
	/* x0 holds load offset */
	ldr	x1, =__rela_start
	ldr	x2, =__rela_end

	b	2f
	/* Loop over the relocations (Elf64_Rela) and process all entries */
1:	ldp	x3, x4, [x1], #16	/* x3 = r_offset, x4 = r_info */
	ldr	x5, [x1], #8		/* x5 = r_addend */
	/*
	 * We're only expecting R_AARCH64_NONE and R_AARCH64_RELATIVE
	 * relocations.
	 */
	cmp	w4, #R_AARCH64_NONE
	b.eq	2f			/* Skip R_AARCH64_NONE */
	cmp	w4, #R_AARCH64_RELATIVE
	b.ne	.
	/*
	 * Update the pointer at r_offset + load_offset with r_addend +
	 * load_offset.
	 */
	add	x5, x5, x0
	/*
	 * Note that we're skipping the load_offset for the address to
	 * update, this is because that memory isn't mapped at that address
	 * yet.
	 */
	str	x5, [x3]
2:	cmp	x1, x2
	b.ne	1b
	ret
END_FUNC relocate
#endif

/*
 * void enable_mmu(unsigned long core_pos);
 *
 * This function depends on being mapped with in the identity map where
 * physical address and virtual address is the same. After MMU has been
 * enabled the instruction pointer will be updated to execute as the new
 * offset instead. Stack pointers and the return address are updated.
 */
LOCAL_FUNC enable_mmu , : , .identity_map
	adr	x1, boot_mmu_config
	load_xregs x1, 0, 2, 6
	/*
	 * x0 = core_pos
	 * x2 = tcr_el1
	 * x3 = mair_el1
	 * x4 = ttbr0_el1_base
	 * x5 = ttbr0_core_offset
	 * x6 = load_offset
	 */
	msr	tcr_el1, x2
	msr	mair_el1, x3

	/*
	 * ttbr0_el1 = ttbr0_el1_base + ttbr0_core_offset * core_pos
	 */
	madd	x1, x5, x0, x4
	msr	ttbr0_el1, x1
	msr	ttbr1_el1, xzr
	isb

	/* Invalidate TLB */
	tlbi	vmalle1

	/*
	 * Make sure translation table writes have drained into memory and
	 * the TLB invalidation is complete.
	 */
	dsb	sy
	isb

	/* Enable the MMU */
	mrs	x1, sctlr_el1
	orr	x1, x1, #SCTLR_M
	msr	sctlr_el1, x1
	isb

	/* Update vbar */
	mrs	x1, vbar_el1
	add	x1, x1, x6
	msr	vbar_el1, x1
	isb

	/* Invalidate instruction cache and branch predictor */
	ic	iallu
	isb

	/* Enable I and D cache */
	mrs	x1, sctlr_el1
	orr	x1, x1, #SCTLR_I
	orr	x1, x1, #SCTLR_C
	msr	sctlr_el1, x1
	isb

	/* Adjust stack pointers and return address */
	msr	spsel, #1
	add	sp, sp, x6
	msr	spsel, #0
	add	sp, sp, x6
	add	x30, x30, x6

	ret
END_FUNC enable_mmu

DATA boot_mmu_config , : /* struct core_mmu_config */
	.skip	CORE_MMU_CONFIG_SIZE
END_DATA boot_mmu_config

FUNC cpu_on_handler , :
	mov	x19, x0
	mov	x20, x1
	mov	x21, x30

	adr	x0, reset_vect_table
	msr	vbar_el1, x0
	isb

	set_sctlr_el1
	isb

	/* Enable aborts now that we can receive exceptions */
	msr	daifclr, #DAIFBIT_ABT

	bl	__get_core_pos
	bl	enable_mmu

	/* Setup SP_EL0 and SP_EL1, SP will be set to SP_EL0 */
	set_sp

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

	.section .identity_map
	.align	11
LOCAL_FUNC reset_vect_table , :, .identity_map
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
