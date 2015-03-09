/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

/*
 * Include(s)
 */
#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>
#include <sm/teesmc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>

/*
 * Booting on 1 or 2 cores ?
 * - currently teecore boot on both cores. It expected 2 cores and synchronise
 *   between the 2 cores execution during boot sequence, mainly to enable
 *   mmu and cache in a coherent way.
 *
 * - If FORCE_UNIPROC is set (internal switch, below), once both core are
 *   booted, only the primary CPU will branch to the next boot stage.
 */

/*
 * Booting linux
 * -------------
 *
 * Current tz init routine is designed to init Secure Mode/Monitor, switch to
 * NSec world and boot a linux kernel image pre-loaded in RAM.
 *
 * 1) jumping into linux entries
 *
 * physical address of linux entry routine =
 *  virtual address of the linux entry routine read from vmlinux
 *  - linux configuration value for CONFIG_PAGE_OFFSET
 *  + physical address where linux is loaded by bootloader or GDB
 *
 *  PRIMARY_STARTUP_PHYS is set by build env and defines linux boot CPU physical entry.
 *  SECONDARY_STARTUP_PHYS is set by build env and defines linux econdary CPUs
 *  entry physical address.
 *
 * 2) linux boot arguments (CONFIG_TEE_GDB_BOOT)
 *
 * In current setup (GDB boot), when here, DDR is ready, linux and tee images
 * are loaded in DDR, linux boot arguments are stored in DDR. CPU0 register
 * R0 = 0, R1 = linux machine ID, R2 = devtree/atags address.
 *
 * Since the current GDB boot, the content of registers R0, R1, and R2 should
 * be preserved (backed-up) for restore once Secure inits are done and CPUs
 * jump to linux kernel entry in Nsec mode.
 * To do so, save R0/R1/R2 to R10/R11/R12, which are preserved by all
 * execution code until a stack is setup for the inits, for CPU0.
 */

/* Image */
.equ stext, STEXT
.equ stm_secondary_startup, STM_SECONDARY_STARTUP

/* Global Functions */
.global tz_sinit


/*
 * Semaphore to let primary CPU runs its inits
 * before secondary CPUs run their own inits
 */
.equ SEM_NOT_READY, 2
.equ SEM_CPU0_READY, 4
.equ SEM_CPU1_READY, 8

.section .data
.balign 4

sem_cpu_sync:
	.word SEM_NOT_READY;

#ifdef CONFIG_TEE_GDB_BOOT
gdb_bootargs:
	.word 0
	.word 0
	.word 0
	.word 0
#endif

	.section .vector_table
	.align 5
	.code 32

initial_vector:
	b	tz_sinit
	b	.	/* Undef */
	b	.	/* Syscall */
	b	.	/* Prefetch abort */
	b	.	/* Data abort */
	b	.	/* Reserved */
	b	.	/* IRQ */
	b	.	/* FIQ */

/*
 * Vector Table Initialization Function
 *
 * Use scratables registers R0-R3.
 * No stack usage. stack is setup by this routine
 * LR store return address.
 */
.section .text
.code 32
.balign 4

secure_init_vector_table:
	/* Set initial vector table base registers (VBAR and MVBAR) */
	ldr	r0, =initial_vector

	/* write VBAR (Secure Mode Vector Base Address Register) */
	mcr	p15, 0, r0, c12, c0, 0

	/* write MVBAR (Monitor Vector Base Address Register) */
	mcr	p15, 0, r0, c12, c0, 1

	bx	lr
/* End of secure_init_vector_table */


/*
 * TrustZone Initialization Function
 */
.section .text
.code 32
.balign 4

tz_sinit:

#ifdef CONFIG_TEE_GDB_BOOT
	/* boot preloaded linux: save linux boot args from GDB */
	mov r10, r0
	mov r11, r1
	mov r12, r2
	/* all following routines, until stack is setup, preserve R10/R11/R12 */
#endif

	/*
	 * Primary CPU and secondary CPUs internal initialization
	 */
	bl arm_secboot_identify_cpu
	bl arm_secboot_early
	bl arm_secboot_errata
	bl secure_init_vector_table

	/* Setup tmp stack */
	bl	get_core_pos
	lsl	r0, #2
	ldr	r1, =stack_tmp_top
	ldr	sp, [r1, r0]

	/*
	 * Case Primary CPU: proceed common cfg
	 * Case secondary CPUs: wait CPU0 is done
	 */
	bl get_core_pos
	cmp r0, #CPU_ID0
	bne _BootCPU1

_BootCPU0:

	/* complete ARM secure MP common configuration */
	bl arm_secboot_late

#ifdef CONFIG_TEE_GDB_BOOT
	ldr r0, =gdb_bootargs
	str r10, [r0, #0]
	str r11, [r0, #4]
	str r12, [r0, #8]
#endif

	/* Cache/MMU Initialization */
	bl arm_cl2_config
	bl arm_cl1_d_invbysetway
	bl arm_cl2_invbyway
	bl arm_cl2_enable

	bl core_init_mmu_map
	bl core_init_mmu_regs
	bl cpu_mmu_enable
	bl cpu_mmu_enable_icache
	bl cpu_mmu_enable_dcache

	/* init BSS */
init_bss:
	ldr r0, =__bss_start
	ldr r2, =__bss_end
	sub r2, r2, r0
	ldr r1, =0
	bl memset

	/* Initialize thread handling and secure monitor */
	ldr	r0, =stext
	bl	main_init

	/* release secondary CPUs */
	ldr r0,=sem_cpu_sync
	ldr r1, =SEM_CPU0_READY
	str r1, [r0]
	dsb

	/* Flush all caches before secondary CPUs setup */
	bl arm_cl1_d_cleaninvbysetway
	bl arm_cl2_cleaninvbyway
	sev

	/* Primary CPU waits secondary  */
	ldr r0,=sem_cpu_sync
	mov r2, #SEM_CPU1_READY
_wait_cpu1:
	ldr r1, [r0]
	cmp r1, r2
	wfene
	bne _wait_cpu1

#ifdef CFG_PL310_LOCKED
	bl arm_cl2_lockallways
	bl arm_cl2_invbyway
#endif

	/* TODO: call teecore inits */

	/* ask monitor to enter NSec from TEE boot sequence */
#ifdef CONFIG_TEE_GDB_BOOT
	/* restore linux boot arguments */
	ldr r4, =gdb_bootargs
	mov r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	ldr r1, [r4, #0]
	ldr r2, [r4, #4]
	ldr r3, [r4, #8]
#endif

	smc	#0
	b	.	/* SMC should not return */

_BootCPU1:

	/* secondary CPUs wait that primary boot CPU have made the MMU/bss inits */
	ldr r0,=sem_cpu_sync
	mov r2, #SEM_CPU0_READY
_wait_cpu0:
	ldr r1, [r0]
	cmp r1, r2
	wfene
	bne _wait_cpu0

	bl arm_secboot_late

	bl arm_cl1_d_cleaninvbysetway
	bl arm_cl2_cleaninvbyway

	bl core_init_mmu_regs
	bl cpu_mmu_enable

	bl cpu_mmu_enable_icache
	bl cpu_mmu_enable_dcache

	/* initialize the asc */
	bl	asc_init

	/* synchronise with CPU0 */
	ldr r0,=sem_cpu_sync
	ldr r1, =SEM_CPU1_READY
	str r1, [r0]
	dsb
	sev

	/* Comment out next line to force booting NSec on 1 core only */
//#define FORCE_UNIPROC
#ifdef FORCE_UNIPROC
	b .
#endif

	/* Initialize thread handling and secure monitor */
	ldr	r0, =stm_secondary_startup
	bl	main_init

	/* initialize the asc */
	bl	asc_init

	mov	r0, #TEESMC_OPTEED_RETURN_ENTRY_DONE
	smc	#0
	b	.	/* SMC should not return */

/* End of tz_sinit */
