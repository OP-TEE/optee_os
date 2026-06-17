/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2019, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2026, Owen O'Hehir
 *
 * RK3506B secondary-core boot pen.
 *
 * Ported in structure from the upstream BSD-3 ARM-TF plat/rockchip
 * pmusram pen (common/aarch32/pmu_sram_cpus_on.S +
 * common/pmusram/cpus_on_fixed_addr.S — the Rockchip "cpuson" model;
 * rk3288 is the ARMv7 analogue).
 *
 * The BootROM releases a parked secondary to RK3506_PEN_PA (a 64 KiB-
 * aligned IRAM slot). The pen long-jumps the core into OP-TEE
 * (TEE_LOAD_ADDR), where the generic CFG_BOOT_SECONDARY_REQUEST path
 * takes over.
 *
 * The blob is fully position-independent (MPIDR read, a PC-relative
 * literal load that stays inside the copied blob, and a patched
 * indirect branch — no relocations, no external literal pool) so
 * psci_rk3506.c copies [rk3506_pen_start, rk3506_pen_end) verbatim into
 * IRAM and patches the single trailing data word.
 *
 * Runs with MMU/caches OFF (BootROM context): all addresses are
 * physical.
 */

	.section .text, "ax"
	.arm
	.balign 8
	.globl rk3506_pen_start
	.globl rk3506_pen_end

/*
 * ARM-TF cpuson per-core gate. The shared BootROM mailbox frees
 * ALL secondaries at once (the first psci_cpu_on), so a core may
 * arrive here before its own psci_cpu_on. It must therefore
 * WFE-poll its own slot and only jump once psci_cpu_on(core) has set
 * slot[core] = OP-TEE secondary entry PA. MMU/caches OFF; all
 * addresses physical; fully position-independent (the trailing data
 * word is patched by psci_rk3506.c after the blob is copied).
 */
rk3506_pen_start:
	mrc	p15, 0, r0, c0, c0, 5	/* r0 = MPIDR */
	and	r0, r0, #0xf		/* r0 = core index (Aff0) */
	ldr	r2, rk3506_pen_slots	/* r2 = RK3506_SLOTS_PA (patched) */
	add	r2, r2, r0, lsl #2	/* r2 = &slot[core] */
1:
	ldr	r3, [r2]		/* r3 = slot[core] */
	cmp	r3, #0			/* set yet? */
	wfeeq				/* no: wait for event (SEV) */
	beq	1b			/* re-check after wake */
	bx	r3			/* yes: -> OP-TEE secondary entry */

	.balign 4
rk3506_pen_slots:
	.word	0			/* patched: RK3506_SLOTS_PA */
rk3506_pen_end:
