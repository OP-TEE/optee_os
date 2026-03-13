/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2025, Linaro Limited
 * Copyright (c) 2021-2023, Arm Limited
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/cache_helpers.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/thread_private_arch.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

.arch_extension sec

.section .data
.balign 4

#ifdef CFG_BOOT_SYNC_CPU
.equ SEM_CPU_READY, 1
#endif

#ifdef CFG_PL310
.section .rodata.init
panic_boot_file:
	.asciz __FILE__

/*
 * void assert_flat_mapped_range(uint32_t vaddr, uint32_t line)
 */
LOCAL_FUNC __assert_flat_mapped_range , :
UNWIND(	.cantunwind)
	push	{ r4-r6, lr }
	mov	r4, r0
	mov	r5, r1
	bl	cpu_mmu_enabled
	cmp	r0, #0
	beq	1f
	mov	r0, r4
	bl	virt_to_phys
	cmp	r0, r4
	beq	1f
	/*
	 * this must be compliant with the panic generic routine:
	 * __do_panic(__FILE__, __LINE__, __func__, str)
	 */
	ldr	r0, =panic_boot_file
	mov	r1, r5
	mov	r2, #0
	mov	r3, #0
	bl	__do_panic
	b	.		/* should NOT return */
1:	pop	{ r4-r6, pc }
END_FUNC __assert_flat_mapped_range

	/* panic if mmu is enable and vaddr != paddr (scratch lr) */
	.macro assert_flat_mapped_range va, line
		ldr	r0, \va
		ldr	r1, =\line
		bl	__assert_flat_mapped_range
	.endm
#endif /* CFG_PL310 */

WEAK_FUNC plat_cpu_reset_early , :
	bx	lr
END_FUNC plat_cpu_reset_early
DECLARE_KEEP_PAGER plat_cpu_reset_early

	.section .identity_map, "ax"
	.align 5
LOCAL_FUNC reset_vect_table , : , .identity_map
	b	.
	b	.	/* Undef */
	b	.	/* Syscall */
	b	.	/* Prefetch abort */
	b	.	/* Data abort */
	b	.	/* Reserved */
	b	.	/* IRQ */
	b	.	/* FIQ */
END_FUNC reset_vect_table

	.macro cpu_is_ready
#ifdef CFG_BOOT_SYNC_CPU
	bl	__get_core_pos
	lsl	r0, r0, #2
	ldr	r1,=sem_cpu_sync
	ldr	r2, =SEM_CPU_READY
	str	r2, [r1, r0]
	dsb
	sev
#endif
	.endm

	.macro wait_primary
#ifdef CFG_BOOT_SYNC_CPU
	ldr	r0, =sem_cpu_sync
	mov	r2, #SEM_CPU_READY
	sev
1:
	ldr	r1, [r0]
	cmp	r1, r2
	wfene
	bne	1b
#endif
	.endm

	.macro wait_secondary
#ifdef CFG_BOOT_SYNC_CPU
	ldr	r0, =sem_cpu_sync
	mov	r3, #CFG_TEE_CORE_NB_CORE
	mov	r2, #SEM_CPU_READY
	sev
1:
	subs	r3, r3, #1
	beq	3f
	add	r0, r0, #4
2:
	ldr	r1, [r0]
	cmp	r1, r2
	wfene
	bne	2b
	b	1b
3:
#endif
	.endm

	/*
	 * set_sctlr : Setup some core configuration in CP15 SCTLR
	 *
	 * Setup required by current implementation of the OP-TEE core:
	 * - Disable data and instruction cache.
	 * - MMU is expected off and exceptions trapped in ARM mode.
	 * - Enable or disable alignment checks upon platform configuration.
	 * - Optionally enable write-implies-execute-never.
	 * - Optionally enable round robin strategy for cache replacement.
	 *
	 * Clobbers r0.
	 */
	.macro set_sctlr
		read_sctlr r0
		bic	r0, r0, #(SCTLR_M | SCTLR_C)
		bic	r0, r0, #SCTLR_I
		bic	r0, r0, #SCTLR_TE
		orr	r0, r0, #SCTLR_SPAN
#if defined(CFG_SCTLR_ALIGNMENT_CHECK)
		orr	r0, r0, #SCTLR_A
#else
		bic	r0, r0, #SCTLR_A
#endif
#if defined(CFG_HWSUPP_MEM_PERM_WXN) && defined(CFG_CORE_RWDATA_NOEXEC)
		orr	r0, r0, #(SCTLR_WXN | SCTLR_UWXN)
#endif
#if defined(CFG_ENABLE_SCTLR_RR)
		orr	r0, r0, #SCTLR_RR
#endif
		write_sctlr r0
	.endm

	.macro maybe_init_spectre_workaround
#if !defined(CFG_WITH_ARM_TRUSTED_FW) && \
    (defined(CFG_CORE_WORKAROUND_SPECTRE_BP) || \
     defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC))
	read_midr r0
	ubfx	r1, r0, #MIDR_IMPLEMENTER_SHIFT, #MIDR_IMPLEMENTER_WIDTH
	cmp	r1, #MIDR_IMPLEMENTER_ARM
	bne	1f
	ubfx	r1, r0, #MIDR_PRIMARY_PART_NUM_SHIFT, \
			#MIDR_PRIMARY_PART_NUM_WIDTH

	movw	r2, #CORTEX_A8_PART_NUM
	cmp	r1, r2
	moveq	r2, #ACTLR_CA8_ENABLE_INVALIDATE_BTB
	beq	2f

	movw	r2, #CORTEX_A15_PART_NUM
	cmp	r1, r2
	moveq	r2, #ACTLR_CA15_ENABLE_INVALIDATE_BTB
	bne	1f	/* Skip it for all other CPUs */
2:
	read_actlr r0
	orr	r0, r0, r2
	write_actlr r0
	isb
1:
#endif
	.endm

FUNC _start , :
UNWIND(	.cantunwind)
	/*
	 * Temporary copy of boot argument registers, will be passed to
	 * boot_save_args() further down.
	 */
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	mov	r8, lr

	/*
	 * 32bit entry is expected to execute Supervisor mode,
	 * some bootloader may enter in Supervisor or Monitor
	 */
	cps	#CPSR_MODE_SVC

	/* Early ARM secure MP specific configuration */
	bl	plat_cpu_reset_early
	maybe_init_spectre_workaround

	set_sctlr
	isb

	ldr	r0, =reset_vect_table
	write_vbar r0

#if defined(CFG_WITH_ARM_TRUSTED_FW)
	b	reset_primary
#else
	bl	__get_core_pos
	cmp	r0, #0
	beq	reset_primary
	b	reset_secondary
#endif
END_FUNC _start
DECLARE_KEEP_INIT _start

	/*
	 * Setup sp to point to the top of the tmp stack for the current CPU:
	 * sp is assigned:
	 *   stack_tmp + (cpu_id + 1) * stack_tmp_stride - STACK_TMP_GUARD
	 */
	.macro set_sp
		bl	__get_core_pos
		cmp	r0, #CFG_TEE_CORE_NB_CORE
		/* Unsupported CPU, park it before it breaks something */
		bge	unhandled_cpu
		add	r0, r0, #1

		/* r2 = stack_tmp - STACK_TMP_GUARD */
		adr	r3, stack_tmp_rel
		ldr	r2, [r3]
		add	r2, r2, r3

		/*
		 * stack_tmp_stride and stack_tmp_stride_rel are the
		 * equivalent of:
		 * extern const u32 stack_tmp_stride;
		 * u32 stack_tmp_stride_rel = (u32)&stack_tmp_stride -
		 *			      (u32)&stack_tmp_stride_rel 
		 *
		 * To load the value of stack_tmp_stride we do the equivalent
		 * of:
		 * *(u32 *)(stack_tmp_stride + (u32)&stack_tmp_stride_rel)
		 */
		adr	r3, stack_tmp_stride_rel
		ldr	r1, [r3]
		ldr	r1, [r1, r3]

		/*
		 * r0 is core pos + 1
		 * r1 is value of stack_tmp_stride
		 * r2 is value of stack_tmp + guard
		 */
		mul	r1, r0, r1
		add	sp, r1, r2
	.endm

	/*
	 * Cache maintenance during entry: handle outer cache.
	 * End address is exclusive: first byte not to be changed.
	 * Note however arm_clX_inv/cleanbyva operate on full cache lines.
	 *
	 * Use ANSI #define to trap source file line number for PL310 assertion
	 */
	.macro __inval_cache_vrange vbase, vend, line
#if defined(CFG_PL310) && !defined(CFG_PL310_SIP_PROTOCOL)
		assert_flat_mapped_range (\vbase), (\line)
		bl	pl310_base
		ldr	r1, \vbase
		ldr	r2, =\vend
		ldr	r2, [r2]
		bl	arm_cl2_invbypa
#endif
		ldr	r0, \vbase
		ldr	r1, =\vend
		ldr	r1, [r1]
		sub	r1, r1, r0
		bl	dcache_inv_range
	.endm

	.macro __flush_cache_vrange vbase, vend, line
#if defined(CFG_PL310) && !defined(CFG_PL310_SIP_PROTOCOL)
		assert_flat_mapped_range (\vbase), (\line)
		ldr	r0, \vbase
		ldr	r1, =\vend
		ldr	r1, [r1]
		sub	r1, r1, r0
		bl	dcache_clean_range
		bl	pl310_base
		ldr	r1, \vbase
		ldr	r2, =\vend
		ldr	r2, [r2]
		bl	arm_cl2_cleaninvbypa
#endif
		ldr	r0, \vbase
		ldr	r1, =\vend
		ldr	r1, [r1]
		sub	r1, r1, r0
		bl	dcache_cleaninv_range
	.endm

#define inval_cache_vrange(vbase, vend) \
		__inval_cache_vrange vbase, vend, __LINE__

#define flush_cache_vrange(vbase, vend) \
		__flush_cache_vrange vbase, vend, __LINE__

#ifdef CFG_BOOT_SYNC_CPU
#define flush_cpu_semaphores \
		flush_cache_vrange(sem_cpu_sync_start, sem_cpu_sync_end)
#else
#define flush_cpu_semaphores
#endif

LOCAL_FUNC reset_primary , : , .identity_map
UNWIND(	.cantunwind)

	/* preserve r4-r8: bootargs */

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
	ldr	r0, =__init_start	/* dst */
	ldr	r1, =__data_end 	/* src */
	ldr	r2, =__init_end
	sub	r2, r2, r0		/* init len */
	ldr	r12, [r1, r2]		/* length of hashes etc */
	add	r2, r2, r12		/* length of init and hashes etc */
	/* Copy backwards (as memmove) in case we're overlapping */
	add	r0, r0, r2		/* __init_start + len */
	add	r1, r1, r2		/* __data_end + len */
	ldr	r3, =boot_cached_mem_end
	str	r0, [r3]
	ldr	r2, =__init_start
copy_init:
	ldmdb	r1!, {r3, r9-r12}
	stmdb	r0!, {r3, r9-r12}
	cmp	r0, r2
	bgt	copy_init
#else
	/*
	 * The binary is built as:
	 * [Core, rodata and data] : In correct location
	 * [struct boot_embdata + data] : Should be moved to right before
	 * __vcore_free_end, the first uint32_t tells the length of the
	 * struct + data
	 */
	ldr	r1, =__data_end		/* src */
	ldr	r2, [r1]		/* struct boot_embdata::total_len */
	/* dst */
	ldr	r0, =__vcore_free_end
	sub	r0, r0, r2
	/* round down to beginning of page */
	mov	r3,  #(SMALL_PAGE_SIZE - 1)
	bic	r0, r0, r3
	ldr	r3, =boot_embdata_ptr
	str	r0, [r3]
	/* Copy backwards (as memmove) in case we're overlapping */
	add	r1, r1, r2
	add	r2, r0, r2
	ldr	r3, =boot_cached_mem_end
	str	r2, [r3]

copy_init:
	ldmdb	r1!, {r3, r9-r12}
	stmdb	r2!, {r3, r9-r12}
	cmp	r2, r0
	bgt	copy_init
#endif

	/*
	 * Clear .bss, this code obviously depends on the linker keeping
	 * start/end of .bss at least 8 byte aligned.
	 */
	ldr	r0, =__bss_start
	ldr	r1, =__bss_end
	mov	r2, #0
	mov	r3, #0
clear_bss:
	stmia	r0!, {r2, r3}
	cmp	r0, r1
	bls	clear_bss

#ifdef CFG_NS_VIRTUALIZATION
	/*
	 * Clear .nex_bss, this code obviously depends on the linker keeping
	 * start/end of .bss at least 8 byte aligned.
	 */
	ldr	r0, =__nex_bss_start
	ldr	r1, =__nex_bss_end
	mov	r2, #0
	mov	r3, #0
clear_nex_bss:
	stmia	r0!, {r2, r3}
	cmp	r0, r1
	bls	clear_nex_bss
#endif

#ifdef CFG_CORE_SANITIZE_KADDRESS
	/* First initialize the entire shadow area with no access */
	ldr	r0, =__asan_shadow_start	/* start */
	ldr	r1, =__asan_shadow_end	/* limit */
	mov	r2, #ASAN_DATA_RED_ZONE
shadow_no_access:
	str	r2, [r0], #4
	cmp	r0, r1
	bls	shadow_no_access

#if !defined(CFG_DYN_CONFIG)
	/* Mark the entire stack area as OK */
	ldr	r2, =CFG_ASAN_SHADOW_OFFSET
	ldr	r0, =__nozi_stack_start	/* start */
	lsr	r0, r0, #ASAN_BLOCK_SHIFT
	add	r0, r0, r2
	ldr	r1, =__nozi_stack_end	/* limit */
	lsr	r1, r1, #ASAN_BLOCK_SHIFT
	add	r1, r1, r2
	mov	r2, #0
shadow_stack_access_ok:
	strb	r2, [r0], #1
	cmp	r0, r1
	bls	shadow_stack_access_ok
#endif
#endif

#if defined(CFG_DYN_CONFIG)
#ifdef CFG_WITH_PAGER
	ldr	r0, =__vcore_free_end
#else
	ldr	r0, =boot_embdata_ptr
	ldr	r0, [r0]
#endif
	sub	r1, r0, #THREAD_BOOT_INIT_TMP_ALLOC

	/* Clear the allocated struct thread_core_local */
	add	r2, r1, #THREAD_CORE_LOCAL_SIZE
	mov	r3, #0
1:	str	r3, [r2, #-4]!
	cmp	r2, r1
	bgt	1b

	sub	r0, r0, #(__STACK_TMP_OFFS + __STACK_CANARY_SIZE)
	mov	r2, #THREAD_ID_INVALID
	str	r2, [r1, #THREAD_CORE_LOCAL_CURR_THREAD]
	mov	r2, #THREAD_CLF_TMP
	str	r2, [r1, #THREAD_CORE_LOCAL_FLAGS]
	str	r0, [r1, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	add	r2, r1, #(THREAD_BOOT_INIT_TMP_ALLOC / 2)
	sub	r2, r2, #__STACK_CANARY_SIZE
	str	r2, [r1, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	mov	sp, r0
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	cps	#CPSR_MODE_ABT
	mov	sp, r1
	cps	#CPSR_MODE_UND
	mov	sp, r1
	cps	#CPSR_MODE_SVC
	/*
	 * Record a single core, to be changed later before secure world
	 * boot is done.
	 */
	ldr	r2, =thread_core_local
	str	r1, [r2]
	ldr	r2, =thread_core_count
	mov	r0, #1
	str	r0, [r2]
#else
	set_sp

	/* Initialize thread_core_local[current_cpu_id] for early boot */
	bl	thread_get_core_local
	push	{r0,r1}
	bl	thread_get_abt_stack
	pop	{r1,r2}
	mov	r3, sp

	cps	#CPSR_MODE_IRQ
	mov	sp, r3
	cps	#CPSR_MODE_FIQ
	mov	sp, r3
	cps	#CPSR_MODE_ABT
	mov	sp, r1
	cps	#CPSR_MODE_UND
	mov	sp, r1
	cps	#CPSR_MODE_SVC

	str	sp, [r1, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	str	r0, [r1, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	mov	r0, #THREAD_ID_INVALID
	str	r0, [r1, #THREAD_CORE_LOCAL_CURR_THREAD]
	mov	r0, #THREAD_CLF_TMP
	str	r0, [r1, #THREAD_CORE_LOCAL_FLAGS]
#endif

	/* complete ARM secure MP common configuration */
	bl	plat_primary_init_early

	/* Enable Console */
	bl	console_init

	mov	r0, r8
	mov	r1, #0
	push	{r0, r1}
	mov	r0, r4
	mov	r1, r5
	mov	r2, r6
	mov	r3, r7
	bl	boot_save_args
	add	sp, sp, #(2 * 4)

	ldr	r0, =__vcore_free_start
	ldr	r2, =__vcore_free_end
#ifdef CFG_WITH_PAGER
#ifdef CFG_DYN_CONFIG
	sub	r1, r2, #THREAD_BOOT_INIT_TMP_ALLOC
#else
	mov	r1, r2
#endif
#else
	ldr	r1, =boot_embdata_ptr
	ldr	r1, [r1]
#ifdef CFG_DYN_CONFIG
	sub	r1, r1, #THREAD_BOOT_INIT_TMP_ALLOC
#endif
#endif
	bl	boot_mem_init

#ifdef CFG_PL310
	bl	pl310_base
	bl	arm_cl2_config
#endif

	/*
	 * Invalidate dcache for all memory used during initialization to
	 * avoid nasty surprices when the cache is turned on. We must not
	 * invalidate memory not used by OP-TEE since we may invalidate
	 * entries used by for instance ARM Trusted Firmware.
	 */
	inval_cache_vrange(cached_mem_start, boot_cached_mem_end)

#if defined(CFG_PL310) && !defined(CFG_PL310_SIP_PROTOCOL)
	/* Enable PL310 if not yet enabled */
	bl	pl310_base
	bl	arm_cl2_enable
#endif

#if !defined(CFG_WITH_ARM_TRUSTED_FW)
	ldr	r0, =thread_core_local
	ldr	r0, [r0]
	ldr	r1, =thread_core_local_pa
	str	r0, [r1]
#endif

#ifdef CFG_CORE_ASLR
	bl	get_aslr_seed
#ifdef CFG_CORE_ASLR_SEED
	mov_imm	r0, CFG_CORE_ASLR_SEED
#endif
#else
	mov	r0, #0
#endif

	ldr	r1, =boot_mmu_config
	bl	core_init_mmu_map

#ifdef CFG_CORE_ASLR
	/*
	 * Save a pointer to thread_core_local[core_pos] since we can't
	 * call thread_get_core_local() again before the recorded end_va's
	 * have been updated below.
	 */
	bl	thread_get_core_local
	mov	r4, r0

	/*
	 * Process relocation information for updating with the virtual map
	 * offset.  We're doing this now before MMU is enabled as some of
	 * the memory will become write protected.
	 */
	ldr	r0, =boot_mmu_config
	ldr	r0, [r0, #CORE_MMU_CONFIG_MAP_OFFSET]
	/*
	 * Update boot_cached_mem_end address with load offset since it was
	 * calculated before relocation.
	 */
	ldr	r3, =boot_cached_mem_end
	ldr	r2, [r3]
	add	r2, r2, r0
	str	r2, [r3]

	bl	relocate
#endif

	bl	__get_core_pos
	bl	enable_mmu
#ifdef CFG_CORE_ASLR
	/*
	 * Update recorded end_va, we depend on r4 pointing to the
	 * pre-relocated thread_core_local[core_pos].
	 *
	 * This must be done before calling into C code to make sure that
	 * the stack pointer matches what we have in thread_core_local[].
	 */
	ldr	r1, =boot_mmu_config
	ldr	r1, [r1, #CORE_MMU_CONFIG_MAP_OFFSET]
#if defined(CFG_DYN_CONFIG)
	ldr	r0, =thread_core_local
	add	r2, r4, r1
	str	r2, [r0]
#endif
	add	r4, r4, r1
	ldr	r0, [r4, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	add	r0, r0, r1
	str	r0, [r4, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	ldr	r0, [r4, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	add	r0, r0, r1
	str	r0, [r4, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]

	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	cps	#CPSR_MODE_ABT
	mov	sp, r4
	cps	#CPSR_MODE_UND
	mov	sp, r4
	cps	#CPSR_MODE_SVC

	/* Update relocations recorded with boot_mem_add_reloc() */
	ldr	r0, =boot_mmu_config
	ldr	r0, [r0, #CORE_MMU_CONFIG_MAP_OFFSET]
	bl	boot_mem_relocate
	/*
	 * Reinitialize console, since register_serial_console() has
	 * previously registered a PA and with ASLR the VA is different
	 * from the PA.
	 */
	bl	console_init
#endif

#ifdef CFG_NS_VIRTUALIZATION
	/*
	 * Initialize partition tables for each partition to
	 * default_partition which has been relocated now to a different VA
	 */
	bl	core_mmu_set_default_prtn_tbl
#endif

	bl	boot_init_primary_early
	bl	boot_init_primary_late

#if defined(CFG_DYN_CONFIG)
#if !defined(CFG_WITH_ARM_TRUSTED_FW)
	/* Update thread_core_local_pa with a new physical address */
	ldr	r0, =__thread_core_local_new
	ldr	r0, [r0]
	bl	virt_to_phys
	ldr	r1, =thread_core_local_pa
	str	r0, [r1]
#endif
	bl	__get_core_pos

	/*
	 * Switch to the new thread_core_local and thread_core_count and
	 * keep the pointer to the new thread_core_local in r1.
	 */
	ldr	r1, =__thread_core_count_new
	ldr	r1, [r1]
	ldr 	r2, =thread_core_count;
	str	r1, [r2]
	ldr	r1, =__thread_core_local_new
	ldr	r1, [r1]
	ldr	r2, =thread_core_local
	str	r1, [r2]

	/*
	 * Update to use the new stacks and thread_core_local. Clear
	 * thread_core_local[0].stackcheck_recursion now that the stack
	 * pointer matches recorded information.
	 */
	mov	r2, #THREAD_CORE_LOCAL_SIZE
	/* r3 = r2 * r0 + r1 */
	mla	r3, r2, r0, r1
	ldr	r0, [r3, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	mov	sp, r0
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	cps	#CPSR_MODE_ABT
	mov	sp, r3
	cps	#CPSR_MODE_UND
	mov	sp, r3
	cps	#CPSR_MODE_SVC
#endif

#ifndef CFG_NS_VIRTUALIZATION
	mov	r9, sp
	ldr	r0, =threads
	ldr	r0, [r0]
	ldr	r0, [r0, #THREAD_CTX_STACK_VA_END]
	mov	sp, r0
	bl	thread_get_core_local
	mov	r8, r0
	mov	r0, #0
	str	r0, [r8, #THREAD_CORE_LOCAL_FLAGS]
#endif
	bl	boot_init_primary_runtime
	bl	boot_init_primary_final
#ifndef CFG_NS_VIRTUALIZATION
	mov	r0, #THREAD_CLF_TMP
	str	r0, [r8, #THREAD_CORE_LOCAL_FLAGS]
	mov	sp, r9
#endif

#ifdef _CFG_CORE_STACK_PROTECTOR
	/* Update stack canary value */
	sub	sp, sp, #0x8
	mov	r0, sp
	mov	r1, #1
	mov	r2, #0x4
	bl	plat_get_random_stack_canaries
	ldr	r0, [sp]
	ldr	r1, =__stack_chk_guard
	str	r0, [r1]
	add	sp, sp, #0x8
#endif

	/*
	 * In case we've touched memory that secondary CPUs will use before
	 * they have turned on their D-cache, clean and invalidate the
	 * D-cache before exiting to normal world.
	 */
	flush_cache_vrange(cached_mem_start, boot_cached_mem_end)

	/* release secondary boot cores and sync with them */
	cpu_is_ready
	flush_cpu_semaphores
	wait_secondary

#ifdef CFG_PL310_LOCKED
#ifdef CFG_PL310_SIP_PROTOCOL
#error "CFG_PL310_LOCKED must not be defined when CFG_PL310_SIP_PROTOCOL=y"
#endif
	/* lock/invalidate all lines: pl310 behaves as if disable */
	bl	pl310_base
	bl	arm_cl2_lockallways
	bl	pl310_base
	bl	arm_cl2_cleaninvbyway
#endif

	/*
	 * Clear current thread id now to allow the thread to be reused on
	 * next entry. Matches the thread_init_boot_thread() in
	 * boot.c.
	 */
#ifndef CFG_NS_VIRTUALIZATION
	bl 	thread_clr_boot_thread
#endif

#ifdef CFG_CORE_FFA
	ldr	r0, =cpu_on_handler
	/*
	 * Compensate for the virtual map offset since cpu_on_handler() is
	 * called with MMU off.
	 */
	ldr	r1, boot_mmu_config + CORE_MMU_CONFIG_MAP_OFFSET
	sub	r0, r0, r1
	bl	thread_spmc_register_secondary_ep
	b	thread_ffa_msg_wait
#else /* CFG_CORE_FFA */

#if defined(CFG_WITH_ARM_TRUSTED_FW)
	ldr	r0, =boot_mmu_config
	ldr	r0, [r0, #CORE_MMU_CONFIG_MAP_OFFSET]
	ldr	r1, =thread_vector_table
	/* Pass the vector address returned from main_init */
	sub	r1, r1, r0
#else
	/* Initialize secure monitor */
	add	r0, sp, #__STACK_TMP_OFFS
	bl	sm_init
	ldr	r0, =boot_arg_nsec_entry
	ldr	r0, [r0]
	bl	init_sec_mon

	/* Relay standard bootarg #1 and #2 to non-secure entry */
	mov	r4, #0
	mov	r3, r6		/* std bootarg #2 for register R2 */
	mov	r2, r5		/* std bootarg #1 for register R1 */
	mov	r1, #0
#endif /* CFG_WITH_ARM_TRUSTED_FW */

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	/* SMC should not return */
	panic_at_smc_return
#endif /* CFG_CORE_FFA */
END_FUNC reset_primary

#ifdef CFG_BOOT_SYNC_CPU
LOCAL_DATA sem_cpu_sync_start , :
	.word	sem_cpu_sync
END_DATA sem_cpu_sync_start

LOCAL_DATA sem_cpu_sync_end , :
	.word	sem_cpu_sync + (CFG_TEE_CORE_NB_CORE << 2)
END_DATA sem_cpu_sync_end
#endif

LOCAL_DATA cached_mem_start , :
	.word	__text_start
END_DATA cached_mem_start

#ifndef CFG_WITH_PAGER
LOCAL_DATA boot_embdata_ptr , :
	.skip	4
END_DATA boot_embdata_ptr
#endif

LOCAL_FUNC unhandled_cpu , :
	wfi
	b	unhandled_cpu
END_FUNC unhandled_cpu

#ifdef CFG_CORE_ASLR
LOCAL_FUNC relocate , :
	push	{r4-r5}
	/* r0 holds load offset */
#ifdef CFG_WITH_PAGER
	ldr	r12, =__init_end
#else
	ldr	r12, =boot_embdata_ptr
	ldr	r12, [r12]
#endif
	ldr	r2, [r12, #BOOT_EMBDATA_RELOC_OFFSET]
	ldr	r3, [r12, #BOOT_EMBDATA_RELOC_LEN]

	mov_imm	r1, TEE_LOAD_ADDR
	add	r2, r2, r12	/* start of relocations */
	add	r3, r3, r2	/* end of relocations */

	/*
	 * Relocations are not formatted as Rel32, instead they are in a
	 * compressed format created by get_reloc_bin() in
	 * scripts/gen_tee_bin.py
	 *
	 * All the R_ARM_RELATIVE relocations are translated into a list of
	 * 32-bit offsets from TEE_LOAD_ADDR. At each address a 32-bit
	 * value pointed out which increased with the load offset.
	 */

#ifdef CFG_WITH_PAGER
	/*
	 * With pager enabled we can only relocate the pager and init
	 * parts, the rest has to be done when a page is populated.
	 */
	sub	r12, r12, r1
#endif

	b	2f
	/* Loop over the relocation addresses and process all entries */
1:	ldr	r4, [r2], #4
#ifdef CFG_WITH_PAGER
	/* Skip too large addresses */
	cmp	r4, r12
	bge	2f
#endif
	ldr	r5, [r4, r1]
	add	r5, r5, r0
	str	r5, [r4, r1]

2:	cmp	r2, r3
	bne	1b

	pop	{r4-r5}
	bx	lr
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
	/* r0 = core pos */
	adr	r1, boot_mmu_config

#ifdef CFG_WITH_LPAE
	ldm	r1!, {r2, r3}
	/*
	 * r2 = ttbcr
	 * r3 = mair0
	 */
	write_ttbcr r2
	write_mair0 r3

	ldm	r1!, {r2, r3}
	/*
	 * r2 = ttbr0_base
	 * r3 = ttbr0_core_offset
	 */

	/*
	 * ttbr0_el1 = ttbr0_base + ttbr0_core_offset * core_pos
	 */
	mla	r12, r0, r3, r2
	mov	r0, #0
	write_ttbr0_64bit r12, r0
	write_ttbr1_64bit r0, r0
#else
	ldm	r1!, {r2, r3}
	/*
	 * r2 = prrr
	 * r3 = nmrr
	 */
	write_prrr r2
	write_nmrr r3

	ldm	r1!, {r2, r3}
	/*
	 * r2 = dacr
	 * r3 = ttbcr
	 */
	write_dacr r2
	write_ttbcr r3

	ldm	r1!, {r2}
	/* r2 = ttbr */
	write_ttbr0 r2
	write_ttbr1 r2

	mov	r2, #0
	write_contextidr r2
#endif
	ldm	r1!, {r2}
	/* r2 = load_offset (always 0 if CFG_CORE_ASLR=n) */
	isb

	/* Invalidate TLB */
	write_tlbiall

	/*
	 * Make sure translation table writes have drained into memory and
	 * the TLB invalidation is complete.
	 */
	dsb	sy
	isb

	read_sctlr r0
	orr	r0, r0, #SCTLR_M
#ifndef CFG_WITH_LPAE
	/* Enable Access flag (simplified access permissions) and TEX remap */
	orr	r0, r0, #(SCTLR_AFE | SCTLR_TRE)
#endif
	write_sctlr r0
	isb

	/* Update vbar */
	read_vbar r1
	add	r1, r1, r2
	write_vbar r1
	isb

	/* Invalidate instruction cache and branch predictor */
	write_iciallu
	write_bpiall
	isb

	read_sctlr r0
	/* Enable I and D cache */
	orr	r0, r0, #SCTLR_I
	orr	r0, r0, #SCTLR_C
#if defined(CFG_ENABLE_SCTLR_Z)
	/*
	 * This is only needed on ARMv7 architecture and hence conditionned
	 * by configuration directive CFG_ENABLE_SCTLR_Z. For recent
	 * architectures, the program flow prediction is automatically
	 * enabled upon MMU enablement.
	 */
	orr	r0, r0, #SCTLR_Z
#endif
	write_sctlr r0
	isb

	/* Adjust stack pointer and return address */
	add	sp, sp, r2
	add	lr, lr, r2

	bx	lr
END_FUNC enable_mmu

#if !defined(CFG_DYN_CONFIG)
LOCAL_DATA stack_tmp_rel , :
	.word	stack_tmp - stack_tmp_rel - STACK_TMP_GUARD
END_DATA stack_tmp_rel

LOCAL_DATA stack_tmp_stride_rel , :
	.word	stack_tmp_stride - stack_tmp_stride_rel
END_DATA stack_tmp_stride_rel
#endif

DATA boot_mmu_config , : /* struct core_mmu_config */
	.skip	CORE_MMU_CONFIG_SIZE
END_DATA boot_mmu_config

#if defined(CFG_WITH_ARM_TRUSTED_FW)
FUNC cpu_on_handler , : , .identity_map
UNWIND(	.cantunwind)
	mov	r4, r0
	mov	r5, r1
	mov	r6, lr

	set_sctlr
	isb

	ldr	r0, =reset_vect_table
	write_vbar r0

	mov	r4, lr

	bl	__get_core_pos
	bl	enable_mmu

	/*
	 * Use the stacks from thread_core_local.
	 */
	bl	__get_core_pos
	ldr	r1, =thread_core_local
	ldr	r1, [r1]
	mov	r2, #THREAD_CORE_LOCAL_SIZE
	/* r3 = r2 * r0 + r1 */
	mla	r3, r2, r0, r1
	ldr	r0, [r3, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	mov	sp, r0
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	cps	#CPSR_MODE_ABT
	mov	sp, r3
	cps	#CPSR_MODE_UND
	mov	sp, r3
	cps	#CPSR_MODE_SVC

	mov	r0, r4
	mov	r1, r5
	bl	boot_cpu_on_handler
#ifdef CFG_CORE_FFA
	b	thread_ffa_msg_wait
#else
	bx	r6
#endif
END_FUNC cpu_on_handler
DECLARE_KEEP_PAGER cpu_on_handler

#else /* defined(CFG_WITH_ARM_TRUSTED_FW) */

LOCAL_FUNC reset_secondary , : , .identity_map
UNWIND(	.cantunwind)
	ldr	r0, =reset_vect_table
	write_vbar r0

	wait_primary

	/*
	 * Initialize stack pointer from thread_core_local, compensate for
	 * ASLR if enabled.
	 */
#ifdef CFG_CORE_ASLR
	ldr	r4, boot_mmu_config + CORE_MMU_CONFIG_MAP_OFFSET
#endif
	bl	__get_core_pos
	ldr	r1, =thread_core_local_pa
#ifdef CFG_CORE_ASLR
	sub	r1, r1, r4
#endif
	ldr	r1, [r1]
	mov	r2, #THREAD_CORE_LOCAL_SIZE
	/* r3 = r2 * r0 + r1 */
	mla	r3, r2, r0, r1
	ldr	r0, [r3, #THREAD_CORE_LOCAL_TMP_STACK_PA_END]
	mov	sp, r0

#if defined (CFG_BOOT_SECONDARY_REQUEST)
	/* if L1 is not invalidated before, do it here */
	mov	r0, #DCACHE_OP_INV
	bl	dcache_op_level1
#endif

	bl	__get_core_pos
	bl	enable_mmu

	/*
	 * Use the stacks from thread_core_local.
	 */
	bl	__get_core_pos
	ldr	r1, =thread_core_local
	ldr	r1, [r1]
	mov	r2, #THREAD_CORE_LOCAL_SIZE
	/* r3 = r2 * r0 + r1 */
	mla	r3, r2, r0, r1
	ldr	r0, [r3, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	mov	sp, r0
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	cps	#CPSR_MODE_ABT
	mov	sp, r3
	cps	#CPSR_MODE_UND
	mov	sp, r3
	cps	#CPSR_MODE_SVC

	cpu_is_ready

#if defined (CFG_BOOT_SECONDARY_REQUEST)
	/*
	 * boot_core_hpen() return value (r0) is address of
	 * ns entry context structure
	 */
	bl	boot_core_hpen
	ldm	r0, {r0, r6}
	mov	r8, r0
#else
	mov	r6, #0
#endif
	bl	boot_init_secondary

	/* Initialize secure monitor */
	add	r0, sp, #__STACK_TMP_OFFS
	bl	sm_init
	mov	r0, r8		/* ns-entry address */
	bl	init_sec_mon

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	mov	r1, r6
	mov	r2, #0
	mov	r3, #0
	mov	r4, #0
	smc	#0
	/* SMC should not return */
	panic_at_smc_return
END_FUNC reset_secondary
DECLARE_KEEP_PAGER reset_secondary
#endif /* defined(CFG_WITH_ARM_TRUSTED_FW) */
