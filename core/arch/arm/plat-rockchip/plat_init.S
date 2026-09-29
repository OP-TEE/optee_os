/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <kernel/cache_helpers.h>

FUNC plat_cpu_reset_early , :

#if defined(PLATFORM_FLAVOR_rv1106)
	/*
	 * The boot loader loads OP-TEE and the images it hands on into DRAM
	 * through its write-back D-cache without cleaning to the Point of
	 * Coherency, and OP-TEE's early boot invalidates the D-cache, which
	 * would discard those still-dirty lines. Clean the whole D-cache to
	 * PoC first. dcache_op_all needs a stack and preserves r4-r12 (so the
	 * boot args _start stashed there survive); sp is set up for real later
	 * in _start, so borrow the top of TZDRAM as a temporary stack.
	 * r4 is filler for alignment.
	 */
	ldr	sp, =(CFG_TZDRAM_START + CFG_TZDRAM_SIZE)
	push	{r4, lr}
	mov	r0, #DCACHE_OP_CLEAN
	bl	dcache_op_all
	pop	{r4, lr}
	dsb
	isb

	/*
	 * Program CNTFRQ (the SPL leaves it at 0). The non-secure zImage
	 * decompressor and the kernel arch-timer read it for delay loops,
	 * so a zero value hangs the decompressor before start_kernel. With
	 * no TF-A in the boot chain, programming it is the secure monitor's
	 * duty. CNTFRQ is secure-writable.
	 */
	mov_imm	r0, 24000000
	write_cntfrq r0

	/*
	 * Grant the non-secure world access to the FPU / Advanced SIMD
	 * (CP10/CP11) and set NS-SMP. The reset value denies NS any
	 * floating-point, so the non-secure zImage decompressor and kernel
	 * would fault on the first NEON instruction (there is no TF-A to
	 * set this up). CNTVOFF is zeroed by sm_init() via CFG_INIT_CNTVOFF,
	 * so it is not handled here.
	 */
	read_nsacr r0
	orr	r0, r0, #(NSACR_CP10 | NSACR_CP11)
	orr	r0, r0, #NSACR_NS_SMP
	write_nsacr r0
	isb
#endif

	/* Enable SMP bit */
	read_actlr  r0
	orr     r0, r0, #ACTLR_SMP
	write_actlr r0
	bx	lr
END_FUNC plat_cpu_reset_early
