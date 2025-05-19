/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2025, Linaro Limited
 * Copyright (c) 2021-2023, Arm Limited
 */

#include <platform_config.h>

#include <arm.h>
#include <arm64_macros.S>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/thread_private_arch.h>
#include <mm/core_mmu.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

	/*
	 * Setup SP_EL0 and SPEL1, SP will be set to SP_EL0.
	 * SP_EL0 is assigned:
	 *   stack_tmp + (cpu_id + 1) * stack_tmp_stride - STACK_TMP_GUARD
	 * SP_EL1 is assigned thread_core_local[cpu_id]
	 */
	.macro set_sp
		bl	__get_core_pos
		cmp	x0, #CFG_TEE_CORE_NB_CORE
		/* Unsupported CPU, park it before it breaks something */
		bge	unhandled_cpu
		add	x0, x0, #1
		adr_l	x1, stack_tmp_stride
		ldr	w1, [x1]
		mul	x1, x0, x1

		/* x0 = stack_tmp - STACK_TMP_GUARD */
		adr_l	x2, stack_tmp_rel
		ldr	w0, [x2]
		add	x0, x0, x2

		msr	spsel, #0
		add	sp, x1, x0
		bl	thread_get_core_local
		msr	spsel, #1
		mov	sp, x0
		msr	spsel, #0
	.endm

	.macro read_feat_mte reg
		mrs	\reg, id_aa64pfr1_el1
		ubfx	\reg, \reg, #ID_AA64PFR1_EL1_MTE_SHIFT, #4
	.endm

	.macro read_feat_pan reg
		mrs	\reg, id_mmfr3_el1
		ubfx	\reg, \reg, #ID_MMFR3_EL1_PAN_SHIFT, #4
	.endm

	.macro set_sctlr_el1
		mrs	x0, sctlr_el1
		orr	x0, x0, #SCTLR_I
		orr	x0, x0, #SCTLR_SA
		orr	x0, x0, #SCTLR_SPAN
#if defined(CFG_CORE_RWDATA_NOEXEC)
		orr	x0, x0, #SCTLR_WXN
#endif
#if defined(CFG_SCTLR_ALIGNMENT_CHECK)
		orr	x0, x0, #SCTLR_A
#else
		bic	x0, x0, #SCTLR_A
#endif
#ifdef CFG_MEMTAG
		read_feat_mte x1
		cmp	w1, #1
		b.ls	111f
		orr	x0, x0, #(SCTLR_ATA | SCTLR_ATA0)
		bic	x0, x0, #SCTLR_TCF_MASK
		bic	x0, x0, #SCTLR_TCF0_MASK
111:
#endif
#if defined(CFG_TA_PAUTH) && defined(CFG_TA_BTI)
		orr	x0, x0, #SCTLR_BT0
#endif
#if defined(CFG_CORE_PAUTH) && defined(CFG_CORE_BTI)
		orr	x0, x0, #SCTLR_BT1
#endif
		msr	sctlr_el1, x0
	.endm

	.macro init_memtag_per_cpu
		read_feat_mte x0
		cmp	w0, #1
		b.ls	11f

#ifdef CFG_TEE_CORE_DEBUG
		/*
		 * This together with GCR_EL1.RRND = 0 will make the tags
		 * acquired with the irg instruction deterministic.
		 */
		mov_imm	x0, 0xcafe00
		msr	rgsr_el1, x0
		/* Avoid tag = 0x0 and 0xf */
		mov	x0, #0
#else
		/*
		 * Still avoid tag = 0x0 and 0xf as we use that tag for
		 * everything which isn't explicitly tagged. Setting
		 * GCR_EL1.RRND = 1 to allow an implementation specific
		 * method of generating the tags.
		 */
		mov	x0, #GCR_EL1_RRND
#endif
		orr	x0, x0, #1
		orr	x0, x0, #(1 << 15)
		msr	gcr_el1, x0

		/*
		 * Enable the tag checks on the current CPU.
		 *
		 * Depends on boot_init_memtag() having cleared tags for
		 * TEE core memory. Well, not really, addresses with the
		 * tag value 0b0000 will use unchecked access due to
		 * TCR_TCMA0.
		 */
		mrs	x0, tcr_el1
		orr	x0, x0, #TCR_TBI0
		orr	x0, x0, #TCR_TCMA0
		msr	tcr_el1, x0

		mrs	x0, sctlr_el1
		orr	x0, x0, #SCTLR_TCF_SYNC
		orr	x0, x0, #SCTLR_TCF0_SYNC
		msr	sctlr_el1, x0

		isb
11:
	.endm

	.macro init_pauth_secondary_cpu
		msr	spsel, #1
		ldp	x0, x1, [sp, #THREAD_CORE_LOCAL_KEYS]
		msr	spsel, #0
		write_apiakeyhi x0
		write_apiakeylo x1
		mrs	x0, sctlr_el1
		orr	x0, x0, #SCTLR_ENIA
		msr	sctlr_el1, x0
		isb
	.endm

	.macro init_pan
		read_feat_pan x0
		cmp	x0, #0
		b.eq	1f
		mrs	x0, sctlr_el1
		bic	x0, x0, #SCTLR_SPAN
		msr	sctlr_el1, x0
		write_pan_enable
	1:
	.endm

FUNC _start , :
	/*
	 * Temporary copy of boot argument registers, will be passed to
	 * boot_save_args() further down.
	 */
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3

	adr	x0, reset_vect_table
	msr	vbar_el1, x0
	isb

#ifdef CFG_PAN
	init_pan
#endif

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
	 * [struct boot_embdata + data] : Should be saved before
	 * initializing pager, first uint32_t tells the length of the data
	 */
	adr	x0, __init_start	/* dst */
	adr	x1, __data_end		/* src */
	adr	x2, __init_end
	sub	x2, x2, x0		/* init len */
	ldr	w4, [x1, x2]		/* length of hashes etc */
	add	x2, x2, x4		/* length of init and hashes etc */
	/* Copy backwards (as memmove) in case we're overlapping */
	add	x0, x0, x2		/* __init_start + len */
	add	x1, x1, x2		/* __data_end + len */
	adr_l	x3, boot_cached_mem_end
	str	x0, [x3]
	adr	x2, __init_start
copy_init:
	ldp	x3, x4, [x1, #-16]!
	stp	x3, x4, [x0, #-16]!
	cmp	x0, x2
	b.gt	copy_init
#else
	/*
	 * The binary is built as:
	 * [Core, rodata and data] : In correct location
	 * [struct boot_embdata + data] : Should be moved to right before
	 * __vcore_free_end, the first uint32_t tells the length of the
	 * struct + data
	 */
	adr_l	x1, __data_end		/* src */
	ldr	w2, [x1]		/* struct boot_embdata::total_len */
	/* dst */
	adr_l	x0, __vcore_free_end
	sub	x0, x0, x2
	/* round down to beginning of page */
	bic	x0, x0, #(SMALL_PAGE_SIZE - 1)
	adr_l	x3, boot_embdata_ptr
	str	x0, [x3]

	/* Copy backwards (as memmove) in case we're overlapping */
	add	x1, x1, x2
	add	x2, x0, x2
	adr_l	x3, boot_cached_mem_end
	str	x2, [x3]

copy_init:
	ldp	x3, x4, [x1, #-16]!
	stp	x3, x4, [x2, #-16]!
	cmp	x2, x0
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

#ifdef CFG_NS_VIRTUALIZATION
	/*
	 * Clear .nex_bss, this code obviously depends on the linker keeping
	 * start/end of .bss at least 8 byte aligned.
	 */
	adr_l	x0, __nex_bss_start
	adr_l	x1, __nex_bss_end
clear_nex_bss:
	str	xzr, [x0], #8
	cmp	x0, x1
	b.lt	clear_nex_bss
#endif

#if defined(CFG_CORE_PHYS_RELOCATABLE)
	/*
	 * Save the base physical address, it will not change after this
	 * point.
	 */
	adr_l	x2, core_mmu_tee_load_pa
	adr	x1, _start		/* Load address */
	str	x1, [x2]

	mov_imm	x0, TEE_LOAD_ADDR	/* Compiled load address */
	sub	x0, x1, x0		/* Relocatation offset */

	cbz	x0, 1f
	bl	relocate
1:
#endif

#ifdef CFG_CORE_SANITIZE_KADDRESS
	/* Initialize the entire shadow area with no access */
	adr_l	x0, __asan_shadow_start	/* start */
	adr_l	x1, __asan_shadow_end	/* limit */
	mov	x2, #ASAN_DATA_RED_ZONE
1:	str	x2, [x0], #8
	cmp	x0, x1
	bls	1b

#if !defined(CFG_DYN_CONFIG)
	/* Mark the entire stack area as OK */
	mov_imm	x2, CFG_ASAN_SHADOW_OFFSET
	adr_l	x0, __nozi_stack_start	/* start */
	lsr	x0, x0, #ASAN_BLOCK_SHIFT
	add	x0, x0, x2
	adr_l	x1, __nozi_stack_end	/* limit */
	lsr	x1, x1, #ASAN_BLOCK_SHIFT
	add	x1, x1, x2
	mov	w2, #0
1:	strb	w2, [x0], #1
	cmp	x0, x1
	bls	1b
#endif
#endif

	/* Setup SP_EL0 and SP_EL1, SP will be set to SP_EL0 */
#if defined(CFG_DYN_CONFIG)
	/*
	 * Point SP_EL0 to a temporary stack with the at the end of mapped
	 * core memory.
	 * Point SP_EL1 a temporary struct thread_core_local before the
	 * temporary stack.
	 */
	adr_l	x0, boot_embdata_ptr
	ldr	x0, [x0]
	sub	x1, x0, #THREAD_BOOT_INIT_TMP_ALLOC

	/* Clear the allocated struct thread_core_local */
	add	x2, x1, #THREAD_CORE_LOCAL_SIZE
1:	stp	xzr, xzr, [x2, #-16]!
	cmp	x2, x1
	bgt	1b

	mov	x2, #THREAD_ID_INVALID
	str	x2, [x1, #THREAD_CORE_LOCAL_CURR_THREAD]
	mov	w2, #THREAD_CLF_TMP
	str	w2, [x1, #THREAD_CORE_LOCAL_FLAGS]
	sub	x0, x0, #(__STACK_CANARY_SIZE / 2)
	str	x0, [x1, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	sub	x2, x0, #(THREAD_BOOT_INIT_TMP_ALLOC / 2)
	str	x2, [x1, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	msr	spsel, #1
	mov	sp, x1
	msr	spsel, #0
	mov	sp, x0
	/*
	 * Record a single core, to be changed later before secure world
	 * boot is done.
	 */
	adr_l	x2, thread_core_local
	str	x1, [x2]
	adr_l	x2, thread_core_count
	mov	x0, #1
	str	x0, [x2]
#else
	set_sp

	/* Initialize thread_core_local[current_cpu_id] for early boot */
	bl	thread_get_abt_stack
	mov	x1, sp
	msr	spsel, #1
	str	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	str	x0, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	mov	x0, #THREAD_ID_INVALID
	str	x0, [sp, #THREAD_CORE_LOCAL_CURR_THREAD]
	mov	w0, #THREAD_CLF_TMP
	str	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	msr	spsel, #0
#endif

	/* Enable aborts now that we can receive exceptions */
	msr	daifclr, #DAIFBIT_ABT

	/*
	 * Invalidate dcache for all memory used during initialization to
	 * avoid nasty surprices when the cache is turned on. We must not
	 * invalidate memory not used by OP-TEE since we may invalidate
	 * entries used by for instance ARM Trusted Firmware.
	 */
	adr_l	x0, __text_start
	adr_l	x1, boot_cached_mem_end
	ldr	x1, [x1]
	sub	x1, x1, x0
	bl	dcache_cleaninv_range

	/* Enable Console */
	bl	console_init

	mov	x0, x19
	mov	x1, x20
	mov	x2, x21
	mov	x3, x22
	mov	x4, xzr
	bl	boot_save_args

	adr_l	x0, __vcore_free_start
	adr_l	x2, __vcore_free_end
#ifdef CFG_WITH_PAGER
	mov	x1, x2
#else
	adr_l	x1, boot_embdata_ptr
	ldr	x1, [x1]
#ifdef CFG_DYN_CONFIG
	sub	x1, x1, #THREAD_BOOT_INIT_TMP_ALLOC
#endif
#endif
	bl	boot_mem_init

#ifdef CFG_MEMTAG
	/*
	 * If FEAT_MTE2 is available, initializes the memtag callbacks.
	 * Tags for OP-TEE core memory are then cleared to make it safe to
	 * enable MEMTAG below.
	 */
	bl	boot_init_memtag
#endif

#ifdef CFG_CORE_ASLR
	bl	get_aslr_seed
#ifdef CFG_CORE_ASLR_SEED
	mov_imm	x0, CFG_CORE_ASLR_SEED
#endif
#else
	mov	x0, #0
#endif

	adr	x1, boot_mmu_config
	bl	core_init_mmu_map

#ifdef CFG_CORE_ASLR
	/*
	 * Process relocation information again updating for the virtual
	 * map offset. We're doing this now before MMU is enabled as some
	 * of the memory will become write protected.
	 */
	ldr	x0, boot_mmu_config + CORE_MMU_CONFIG_MAP_OFFSET
	cbz	x0, 1f
	/*
	 * Update boot_cached_mem_end address with load offset since it was
	 * calculated before relocation.
	 */
	adr_l	x5, boot_cached_mem_end
	ldr	x6, [x5]
	add	x6, x6, x0
	str	x6, [x5]
	adr	x1, _start		/* Load address */
	bl	relocate
1:
#endif

	bl	__get_core_pos
	bl	enable_mmu
#ifdef CFG_CORE_ASLR
#if defined(CFG_DYN_CONFIG)
	/*
	 * thread_core_local holds only one core and thread_core_count is 1
	 * so SP_EL1 points to the updated pointer for thread_core_local.
	 */
	msr	spsel, #1
	mov	x1, sp
	msr	spsel, #0
	adr_l	x0, thread_core_local
	str	x1, [x0]
#endif

	/*
	 * Update recorded end_va. This must be done before calling into C
	 * code to make sure that the stack pointer matches what we have in
	 * thread_core_local[].
	 */
	adr_l	x0, boot_mmu_config
	ldr	x0, [x0, #CORE_MMU_CONFIG_MAP_OFFSET]
	msr	spsel, #1
	ldr	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	add	x1, x1, x0
	str	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	ldr	x1, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	add	x1, x1, x0
	str	x1, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	msr	spsel, #0

	/* Update relocations recorded with boot_mem_add_reloc() */
	adr_l	x0, boot_mmu_config
	ldr	x0, [x0, #CORE_MMU_CONFIG_MAP_OFFSET]
	bl	boot_mem_relocate
	/*
	 * Reinitialize console, since register_serial_console() has
	 * previously registered a PA and with ASLR the VA is different
	 * from the PA.
	 */
	bl	console_init
#endif

#ifdef CFG_MEMTAG
	bl	boot_clear_memtag
#endif

#ifdef CFG_NS_VIRTUALIZATION
	/*
	 * Initialize partition tables for each partition to
	 * default_partition which has been relocated now to a different VA
	 */
	bl	core_mmu_set_default_prtn_tbl
#endif

	bl	boot_init_primary_early

#ifdef CFG_MEMTAG
	init_memtag_per_cpu
#endif
	bl	boot_init_primary_late

#if defined(CFG_DYN_CONFIG)
	bl	__get_core_pos

	/*
	 * Switch to the new thread_core_local and thread_core_count and
	 * keep the pointer to the new thread_core_local in x1.
	 */
	adr_l	x1, __thread_core_count_new
	ldr	x1, [x1]
	adr_l 	x2, thread_core_count;
	str	x1, [x2]
	adr_l	x1, __thread_core_local_new
	ldr	x1, [x1]
	adr_l	x2, thread_core_local
	str	x1, [x2]

	/*
	 * Update SP_EL0 to use the new tmp stack and update SP_EL1 to
	 * point the new thread_core_local and clear
	 * thread_core_local[0].stackcheck_recursion now that the stack
	 * pointer matches recorded information.
	 */
	mov	x2, #THREAD_CORE_LOCAL_SIZE
	/* x3 = x2 * x0 + x1 */
	madd	x3, x2, x0, x1
	ldr	x0, [x3, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	mov	sp, x0
	msr	spsel, #1
	mov	sp, x3
	msr	spsel, #0
#endif

#ifndef CFG_NS_VIRTUALIZATION
	mov	x23, sp
	adr_l	x0, threads
	ldr	x0, [x0]
	ldr	x0, [x0, #THREAD_CTX_STACK_VA_END]
	mov	sp, x0
	bl	thread_get_core_local
	mov	x24, x0
	str	wzr, [x24, #THREAD_CORE_LOCAL_FLAGS]
#endif
	bl	boot_init_primary_runtime
#ifdef CFG_CORE_PAUTH
	adr_l	x0, threads
	ldr	x0, [x0]
	ldp	x1, x2, [x0, #THREAD_CTX_KEYS]
	write_apiakeyhi x1
	write_apiakeylo x2
	mrs	x0, sctlr_el1
	orr	x0, x0, #SCTLR_ENIA
	msr	sctlr_el1, x0
	isb
#endif
	bl	boot_init_primary_final

#ifndef CFG_NS_VIRTUALIZATION
	mov	x0, #THREAD_CLF_TMP
	str     w0, [x24, #THREAD_CORE_LOCAL_FLAGS]
	mov	sp, x23
#ifdef CFG_CORE_PAUTH
	ldp	x0, x1, [x24, #THREAD_CORE_LOCAL_KEYS]
	write_apiakeyhi x0
	write_apiakeylo x1
	isb
#endif
#endif

#ifdef _CFG_CORE_STACK_PROTECTOR
	/* Update stack canary value */
	sub	sp, sp, #0x10
	mov	x0, sp
	mov	x1, #1
	mov	x2, #0x8
	bl	plat_get_random_stack_canaries
	ldr	x0, [sp]
	adr_l	x5, __stack_chk_guard
	str	x0, [x5]
	add	sp, sp, #0x10
#endif

	/*
	 * In case we've touched memory that secondary CPUs will use before
	 * they have turned on their D-cache, clean and invalidate the
	 * D-cache before exiting to normal world.
	 */
	adr_l	x0, __text_start
	adr_l	x1, boot_cached_mem_end
	ldr	x1, [x1]
	sub	x1, x1, x0
	bl	dcache_cleaninv_range

	/*
	 * Clear current thread id now to allow the thread to be reused on
	 * next entry. Matches the thread_init_boot_thread in
	 * boot.c.
	 */
#ifndef CFG_NS_VIRTUALIZATION
	bl 	thread_clr_boot_thread
#endif

#ifdef CFG_CORE_FFA
	adr	x0, cpu_on_handler
	/*
	 * Compensate for the virtual map offset since cpu_on_handler() is
	 * called with MMU off.
	 */
	ldr	x1, boot_mmu_config + CORE_MMU_CONFIG_MAP_OFFSET
	sub	x0, x0, x1
	bl	thread_spmc_register_secondary_ep
	b	thread_ffa_msg_wait
#else
	/*
	 * Pass the vector address returned from main_init Compensate for
	 * the virtual map offset since cpu_on_handler() is called with MMU
	 * off.
	 */
	ldr	x0, boot_mmu_config + CORE_MMU_CONFIG_MAP_OFFSET
	adr	x1, thread_vector_table
	sub	x1, x1, x0
	mov	x0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	/* SMC should not return */
	panic_at_smc_return
#endif
END_FUNC _start
DECLARE_KEEP_INIT _start

#ifndef CFG_WITH_PAGER
	.section .identity_map.data
	.balign	8
LOCAL_DATA boot_embdata_ptr , :
	.skip	8
END_DATA boot_embdata_ptr
#endif

#if defined(CFG_CORE_ASLR) || defined(CFG_CORE_PHYS_RELOCATABLE)
LOCAL_FUNC relocate , :
	/*
	 * x0 holds relocate offset
	 * x1 holds load address
	 */
#ifdef CFG_WITH_PAGER
	adr_l	x6, __init_end
#else
	adr_l	x6, boot_embdata_ptr
	ldr	x6, [x6]
#endif
	ldp	w2, w3, [x6, #BOOT_EMBDATA_RELOC_OFFSET]

	add	x2, x2, x6	/* start of relocations */
	add	x3, x3, x2	/* end of relocations */

	/*
	 * Relocations are not formatted as Rela64, instead they are in a
	 * compressed format created by get_reloc_bin() in
	 * scripts/gen_tee_bin.py
	 *
	 * All the R_AARCH64_RELATIVE relocations are translated into a
	 * list of 32-bit offsets from TEE_LOAD_ADDR. At each address a
	 * 64-bit value pointed out which increased with the load offset.
	 */

#ifdef CFG_WITH_PAGER
	/*
	 * With pager enabled we can only relocate the pager and init
	 * parts, the rest has to be done when a page is populated.
	 */
	sub	x6, x6, x1
#endif

	b	2f
	/* Loop over the relocation addresses and process all entries */
1:	ldr	w4, [x2], #4
#ifdef CFG_WITH_PAGER
	/* Skip too large addresses */
	cmp	x4, x6
	b.ge	2f
#endif
	add	x4, x4, x1
	ldr	x5, [x4]
	add	x5, x5, x0
	str	x5, [x4]

2:	cmp	x2, x3
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

	.section .identity_map.data
	.balign	8
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

#ifdef CFG_PAN
	init_pan
#endif

	/* Enable aborts now that we can receive exceptions */
	msr	daifclr, #DAIFBIT_ABT

	bl	__get_core_pos
	bl	enable_mmu

#if defined(CFG_DYN_CONFIG)
	/*
	 * Update SP_EL0 to use the new tmp stack and update SP_EL1 to
	 * point the new thread_core_local.
	 */
	bl	__get_core_pos
	adr_l	x1, thread_core_local
	ldr	x1, [x1]
	mov	x2, #THREAD_CORE_LOCAL_SIZE
	/* x3 = x2 * x0 + x1 */
	madd	x3, x2, x0, x1
	ldr	x0, [x3, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	mov	sp, x0
	msr	spsel, #1
	mov	sp, x3
	msr	spsel, #0
#else
	/* Setup SP_EL0 and SP_EL1, SP will be set to SP_EL0 */
	set_sp
#endif

#ifdef CFG_MEMTAG
	init_memtag_per_cpu
#endif
#ifdef CFG_CORE_PAUTH
	init_pauth_secondary_cpu
#endif

	mov	x0, x19
	mov	x1, x20
#ifdef CFG_CORE_FFA
	bl	boot_cpu_on_handler
	b	thread_ffa_msg_wait
#else
	mov	x30, x21
	b	boot_cpu_on_handler
#endif
END_FUNC cpu_on_handler
DECLARE_KEEP_PAGER cpu_on_handler

LOCAL_FUNC unhandled_cpu , :
	wfi
	b	unhandled_cpu
END_FUNC unhandled_cpu

#if !defined(CFG_DYN_CONFIG)
LOCAL_DATA stack_tmp_rel , :
	.word	stack_tmp - stack_tmp_rel - STACK_TMP_GUARD
END_DATA stack_tmp_rel
#endif

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

	.section .identity_map, "ax", %progbits
	.align	11
LOCAL_FUNC reset_vect_table , :, .identity_map, , nobti
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

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
