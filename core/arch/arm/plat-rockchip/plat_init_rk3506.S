/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Owen O'Hehir
 *
 * RK3506B-specific per-core early init (plat_cpu_reset_early).
 *
 * RK3506 runs OP-TEE as the highest-privilege secure monitor with no
 * TF-A beneath it, so this performs the per-core CPU init that TF-A
 * does on the AArch64 rockchip flavors (rk3399/px30/rk3588). The ARM32
 * rk322x port is the minimal sibling (plat_init.S sets ACTLR.SMP only);
 * rk3506's boot chain leaves more unprogrammed, so it does more.
 *
 * Notably, unlike rk322x (whose loader programs the architected-timer
 * CNTFRQ before OP-TEE runs), the RK3506B boot chain leaves CNTFRQ at
 * its reset default. Upstream OP-TEE's primary_save_cntfrq()
 * (core/arch/arm/kernel/boot.c) reads CNTFRQ at primary-CPU boot time
 * and stashes it for secondary CPUs; if it reads 0 the timer subsystem
 * fails. Setting CNTFRQ here, before any C runtime, is the standard
 * remedy. The value is 24 MHz (the xin24m crystal frequency).
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>

FUNC plat_cpu_reset_early , :
	/*
	 * 1) Program CNTFRQ_EL0 = 24 MHz (xin24m crystal). The
	 *    architected-timer frequency register must be initialised by a
	 *    higher exception level. On RK3506 we are it.
	 */
	mov_imm	r0, 0x016E3600	/* 24000000 = 24 MHz */
	write_cntfrq r0

	/*
	 * 2) ACTLR.SMP — required for Cortex-A7 multi-core coherency
	 *    (Cortex-A7 ARM TRM "Auxiliary Control Register" section).
	 */
	read_actlr  r0
	orr	r0, r0, #ACTLR_SMP
	write_actlr r0

	/*
	 * 3) NSACR — grant the non-secure world access to CP10/CP11
	 *    (FPU/NEON; without these, NS use of FPU/NEON traps to Undef)
	 *    and to NSACR.NS_SMP (bit 18), which permits the non-secure
	 *    world to set ACTLR.SMP for cache coherency on its cores.
	 *    (Bit definitions in core/arch/arm/include/arm32.h.)
	 */
	read_nsacr r0
	orr	r0, r0, #NSACR_CP10	/* NS FPU            */
	orr	r0, r0, #NSACR_CP11	/* NS NEON           */
	orr	r0, r0, #NSACR_NS_SMP	/* NS ACTLR.SMP write */
	write_nsacr r0

	/*
	 * 4) Clear SCTLR.V — use VBAR-based vector base rather than the
	 *    high-vector default 0xffff0000 (ARMv7-A ARM "System Control
	 *    Register" §B4.1.130). Upstream OP-TEE installs its own
	 *    VBAR shortly, so V must be 0 for VBAR to be effective.
	 */
	read_sctlr r0
	bic	r0, r0, #SCTLR_V
	write_sctlr r0

	/*
	 * 5) Enter Monitor mode with SCR.NS = 1 so the non-secure banked
	 *    SCTLR is reachable for the clear below. CNTVOFF is zeroed by
	 *    sm_init() (CFG_INIT_CNTVOFF), so it is not done here.
	 */
	cps	#CPSR_MODE_MON		/* enter Monitor mode */
	read_scr r0
	orr	r0, r0, #SCR_NS		/* set NS bit */
	write_scr r0
	isb

	/*
	 * With SCR.NS=1, SCTLR refers to the non-secure banked copy. Clear
	 * NS MMU + caches (M/C/I) so a core entering the non-secure world
	 * does so MMU-off, as the kernel's physical secondary entry expects.
	 * A fresh-from-BootROM core already has these clear (no-op); a core
	 * that ran Linux and was offlined via PSCI CPU_OFF would otherwise
	 * re-enter NS with a stale NS MMU enabled and the kernel's secondary
	 * bring-up would fault on the old page tables.
	 */
	read_sctlr r2
	bic	r2, r2, #(SCTLR_M | SCTLR_C)
	bic	r2, r2, #SCTLR_I
	write_sctlr r2
	isb

	read_scr r0
	bic	r0, r0, #SCR_NS		/* clear NS bit */
	write_scr r0
	isb
	cps	#CPSR_MODE_SVC		/* back to Secure SVC */

	bx	lr
END_FUNC plat_cpu_reset_early

/*
 * void __noreturn rk3506_cpu_down(vaddr_t pen_pa);
 *
 * Hand a secondary core back from OP-TEE (MMU on) to the BootROM pen so it
 * re-parks in WFE on its per-core slot, ready for the next psci_cpu_on() to
 * release it as at cold boot. The caller (psci_cpu_off) has already cleared
 * slot[core], cleaned and disabled the D-cache, and exited SMP coherency.
 *
 * Placed in .identity_map so virtual == physical across the MMU disable: once
 * SCTLR.M is cleared the core fetches from physical addresses, and the branch
 * target pen_pa is physical. psci_cpu_off() enters this routine through its
 * physical address, so it runs at VA==PA regardless of CFG_CORE_ASLR.
 *
 *	r0 = pen_pa (physical pen entry)
 */
FUNC rk3506_cpu_down , : , .identity_map
	dsb
	isb

	/* Disable MMU and I-cache (D-cache already off from cpu_off). */
	read_sctlr r1
	bic	r1, r1, #(SCTLR_M | SCTLR_C)
	bic	r1, r1, #SCTLR_I
	write_sctlr r1
	isb

	/* MMU now off: flush TLB, I-cache and branch predictor. */
	write_tlbiall
	write_iciallu
	write_bpiall
	dsb
	isb

	/* Re-enter the pen; it WFE-polls slot[core] (now 0) until cpu_on. */
	bx	r0
END_FUNC rk3506_cpu_down
