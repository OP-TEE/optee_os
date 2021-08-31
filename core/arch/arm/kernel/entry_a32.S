/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2021, Arm Limited
 */

#include <arm32_macros.S>
#include <arm.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/cache_helpers.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

#include "thread_private.h"

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

#if defined(CFG_CORE_SEL1_SPMC) && defined(CFG_WITH_ARM_TRUSTED_FW)
	/*
	 * With OP-TEE as SPMC at S-EL1 the SPMD (SPD_spmd) in TF-A passes
	 * the DTB in r0, pagable part in r1, and the rest of the registers
	 * are unused
	 *
	 * Save boot arguments passed
	 * entry r0, saved r6: device tree address
	 * entry r1, saved r4: pagestore
	 * saved r5, r7: Zero
	 */
	.macro bootargs_entry
	mov	r6, r0
	mov	r4, r1
	mov	r5, #0
	mov	r7, #0
	.endm
#else
	/*
	 * Save boot arguments
	 * entry r0, saved r4: pagestore
	 * entry r1, saved r7: (ARMv7 standard bootarg #1)
	 * entry r2, saved r6: device tree address, (ARMv7 standard bootarg #2)
	 * entry lr, saved r5: non-secure entry address (ARMv7 bootarg #0)
	 */
	.macro bootargs_entry
#if defined(CFG_NS_ENTRY_ADDR)
	ldr	r5, =CFG_NS_ENTRY_ADDR
#else
	mov	r5, lr
#endif
#if defined(CFG_PAGEABLE_ADDR)
	ldr	r4, =CFG_PAGEABLE_ADDR
#else
	mov	r4, r0
#endif
#if defined(CFG_DT_ADDR)
	ldr	r6, =CFG_DT_ADDR
#else
	mov	r6, r2
#endif
	mov	r7, r1
	.endm
#endif

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

	bootargs_entry

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
	 * sp is assigned stack_tmp_export + cpu_id * stack_tmp_stride
	 */
	.macro set_sp
		bl	__get_core_pos
		cmp	r0, #CFG_TEE_CORE_NB_CORE
		/* Unsupported CPU, park it before it breaks something */
		bge	unhandled_cpu

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

		/* Same pattern as for stack_tmp_stride above */
		adr	r3, stack_tmp_export_rel
		ldr	r2, [r3]
		ldr	r2, [r2, r3]

		/*
		 * r0 is core pos
		 * r1 is value of stack_tmp_stride
		 * r2 is value of stack_tmp_export
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
		ldr	r2, \vend
		bl	arm_cl2_invbypa
#endif
		ldr	r0, \vbase
		ldr	r1, \vend
		sub	r1, r1, r0
		bl	dcache_inv_range
	.endm

	.macro __flush_cache_vrange vbase, vend, line
#if defined(CFG_PL310) && !defined(CFG_PL310_SIP_PROTOCOL)
		assert_flat_mapped_range (\vbase), (\line)
		ldr	r0, \vbase
		ldr	r1, \vend
		sub	r1, r1, r0
		bl	dcache_clean_range
		bl	pl310_base
		ldr	r1, \vbase
		ldr	r2, \vend
		bl	arm_cl2_cleaninvbypa
#endif
		ldr	r0, \vbase
		ldr	r1, \vend
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

	/* preserve r4-r7: bootargs */

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
	str	r0, cached_mem_end
	ldr	r2, =__init_start
copy_init:
	ldmdb	r1!, {r3, r8-r12}
	stmdb	r0!, {r3, r8-r12}
	cmp	r0, r2
	bgt	copy_init
#else
	/*
	 * The binary is built as:
	 * [Core, rodata and data] : In correct location
	 * [struct boot_embdata + data] : Should be moved to __end, first
	 * uint32_t tells the length of the struct + data
	 */
	ldr	r0, =__end		/* dst */
	ldr	r1, =__data_end		/* src */
	ldr	r2, [r1]		/* struct boot_embdata::total_len */
	/* Copy backwards (as memmove) in case we're overlapping */
	add	r0, r0, r2
	add	r1, r1, r2
	str	r0, cached_mem_end
	ldr	r2, =__end

copy_init:
	ldmdb	r1!, {r3, r8-r12}
	stmdb	r0!, {r3, r8-r12}
	cmp	r0, r2
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

#ifdef CFG_VIRTUALIZATION
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

	set_sp

	bl	thread_init_thread_core_local

	/* complete ARM secure MP common configuration */
	bl	plat_primary_init_early

	/* Enable Console */
	bl	console_init

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
	inval_cache_vrange(cached_mem_start, cached_mem_end)

#if defined(CFG_PL310) && !defined(CFG_PL310_SIP_PROTOCOL)
	/* Enable PL310 if not yet enabled */
	bl	pl310_base
	bl	arm_cl2_enable
#endif

#ifdef CFG_CORE_ASLR
	mov	r0, r6
	bl	get_aslr_seed
#else
	mov	r0, #0
#endif

	ldr	r1, =boot_mmu_config
	bl	core_init_mmu_map

#ifdef CFG_CORE_ASLR
	/*
	 * Process relocation information for updating with the new offset.
	 * We're doing this now before MMU is enabled as some of the memory
	 * will become write protected.
	 */
	ldr	r0, =boot_mmu_config
	ldr	r0, [r0, #CORE_MMU_CONFIG_LOAD_OFFSET]
	/*
	 * Update cached_mem_end address with load offset since it was
	 * calculated before relocation.
	 */
	ldr	r2, cached_mem_end
	add	r2, r2, r0
	str	r2, cached_mem_end

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

#ifdef CFG_VIRTUALIZATION
	/*
	 * Initialize partition tables for each partition to
	 * default_partition which has been relocated now to a different VA
	 */
	bl	core_mmu_set_default_prtn_tbl
#endif

	mov	r0, r4		/* pageable part address */
	mov	r1, r5		/* ns-entry address */
	bl	boot_init_primary_early
#ifndef CFG_VIRTUALIZATION
	mov	r9, sp
	ldr	r0, =threads
	ldr	r0, [r0, #THREAD_CTX_STACK_VA_END]
	mov	sp, r0
	bl	thread_get_core_local
	mov	r8, r0
	mov	r0, #0
	str	r0, [r8, #THREAD_CORE_LOCAL_FLAGS]
#endif
	mov	r0, r6		/* DT address */
	bl	boot_init_primary_late
#ifndef CFG_VIRTUALIZATION
	mov	r0, #THREAD_CLF_TMP
	str	r0, [r8, #THREAD_CORE_LOCAL_FLAGS]
	mov	sp, r9
#endif

	/*
	 * In case we've touched memory that secondary CPUs will use before
	 * they have turned on their D-cache, clean and invalidate the
	 * D-cache before exiting to normal world.
	 */
	flush_cache_vrange(cached_mem_start, cached_mem_end)

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
#ifndef CFG_VIRTUALIZATION
	bl 	thread_clr_boot_thread
#endif

#ifdef CFG_CORE_FFA
	ldr	r0, =cpu_on_handler
	/*
	 * Compensate for the load offset since cpu_on_handler() is
	 * called with MMU off.
	 */
	ldr	r1, boot_mmu_config + CORE_MMU_CONFIG_LOAD_OFFSET
	sub	r0, r0, r1
	bl	ffa_secondary_cpu_ep_register
	b	thread_ffa_msg_wait
#else /* CFG_CORE_FFA */

#if defined(CFG_WITH_ARM_TRUSTED_FW)
	ldr	r0, =boot_mmu_config
	ldr	r0, [r0, #CORE_MMU_CONFIG_LOAD_OFFSET]
	ldr	r1, =thread_vector_table
	/* Pass the vector address returned from main_init */
	sub	r1, r1, r0
#else
	/* realy standard bootarg #1 and #2 to non secure entry */
	mov	r4, #0
	mov	r3, r6		/* std bootarg #2 for register R2 */
	mov	r2, r7		/* std bootarg #1 for register R1 */
	mov	r1, #0
#endif /* CFG_WITH_ARM_TRUSTED_FW */

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */
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

LOCAL_DATA cached_mem_end , :
	.skip	4
END_DATA cached_mem_end

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
	ldr	r12, =__end
#endif
	ldr	r2, [r12, #BOOT_EMBDATA_RELOC_OFFSET]
	ldr	r3, [r12, #BOOT_EMBDATA_RELOC_LEN]

	mov_imm	r1, TEE_RAM_START
	add	r2, r2, r12	/* start of relocations */
	add	r3, r3, r2	/* end of relocations */

	/*
	 * Relocations are not formatted as Rel32, instead they are in a
	 * compressed format created by get_reloc_bin() in
	 * scripts/gen_tee_bin.py
	 *
	 * All the R_ARM_RELATIVE relocations are translated into a list
	 * list of 32-bit offsets from TEE_RAM_START. At each address a
	 * 32-bit value pointed out which increased with the load offset.
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

LOCAL_DATA stack_tmp_export_rel , :
	.word	stack_tmp_export - stack_tmp_export_rel
END_DATA stack_tmp_export_rel

LOCAL_DATA stack_tmp_stride_rel , :
	.word	stack_tmp_stride - stack_tmp_stride_rel
END_DATA stack_tmp_stride_rel

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

	adr	r0, reset_vect_table
	write_vbar r0

	mov	r4, lr

	bl	__get_core_pos
	bl	enable_mmu

	set_sp

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
	adr	r0, reset_vect_table
	write_vbar r0

	wait_primary

	set_sp
#ifdef CFG_CORE_ASLR
	/*
	 * stack_tmp_export which is used as base when initializing sp has
	 * been relocated to the new offset. Since MMU isn't enabled on
	 * this CPU yet we need to restore the corresponding physical
	 * address.
	 */
	adr	r0, boot_mmu_config
	ldr	r0, [r0, #CORE_MMU_CONFIG_LOAD_OFFSET]
	sub	sp, sp, r0
#endif

#if defined (CFG_BOOT_SECONDARY_REQUEST)
	/* if L1 is not invalidated before, do it here */
	mov	r0, #DCACHE_OP_INV
	bl	dcache_op_level1
#endif

	bl	__get_core_pos
	bl	enable_mmu

	cpu_is_ready

#if defined (CFG_BOOT_SECONDARY_REQUEST)
	/*
	 * boot_core_hpen() return value (r0) is address of
	 * ns entry context structure
	 */
	bl	boot_core_hpen
	ldm	r0, {r0, r6}
#else
	mov	r0, r5		/* ns-entry address */
	mov	r6, #0
#endif
	bl	boot_init_secondary

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	mov	r1, r6
	mov	r2, #0
	mov	r3, #0
	mov	r4, #0
	smc	#0
	b	.	/* SMC should not return */
END_FUNC reset_secondary
DECLARE_KEEP_PAGER reset_secondary
#endif /* defined(CFG_WITH_ARM_TRUSTED_FW) */
