/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2016-2022, Linaro Limited
 * Copyright (c) 2020-2021, Arm Limited
 */

#ifndef __KERNEL_THREAD_ARCH_H
#define __KERNEL_THREAD_ARCH_H

#ifndef __ASSEMBLER__
#include <arm.h>
#include <compiler.h>
#include <kernel/vfp.h>
#include <types_ext.h>
#endif

#ifndef __ASSEMBLER__

#ifdef ARM64
/*
 * struct thread_core_local needs to have alignment suitable for a stack
 * pointer since SP_EL1 points to this
 */
#define THREAD_CORE_LOCAL_ALIGNED __aligned(16)
#else
#define THREAD_CORE_LOCAL_ALIGNED __aligned(8)
#endif

struct mobj;

/*
 * Storage of keys used for pointer authentication. FEAT_PAuth supports a
 * number of keys of which only the APIA key is currently used, depending on
 * configuration.
 */
struct thread_pauth_keys {
	uint64_t apia_hi;
	uint64_t apia_lo;
};

struct thread_core_local {
#ifdef ARM32
	uint32_t r[2];
	paddr_t sm_pm_ctx_phys;
#endif
#ifdef ARM64
	uint64_t x[4];
#endif
#ifdef CFG_CORE_PAUTH
	struct thread_pauth_keys keys;
#endif
	vaddr_t tmp_stack_va_end;
	long kcode_offset;
	short int curr_thread;
	uint32_t flags;
	vaddr_t abt_stack_va_end;
#ifdef CFG_TEE_CORE_DEBUG
	unsigned int locked_count; /* Number of spinlocks held */
#endif
#if defined(ARM64) && defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC)
	uint8_t bhb_loop_count;
#endif
#ifdef CFG_CORE_DEBUG_CHECK_STACKS
	bool stackcheck_recursion;
#endif
} THREAD_CORE_LOCAL_ALIGNED;

struct thread_vector_table {
	uint32_t std_smc_entry;
	uint32_t fast_smc_entry;
	uint32_t cpu_on_entry;
	uint32_t cpu_off_entry;
	uint32_t cpu_resume_entry;
	uint32_t cpu_suspend_entry;
	uint32_t fiq_entry;
	uint32_t system_off_entry;
	uint32_t system_reset_entry;
};

extern struct thread_vector_table thread_vector_table;

struct thread_user_vfp_state {
	struct vfp_state vfp;
	bool lazy_saved;
	bool saved;
};

#ifdef ARM32
struct thread_smc_args {
	uint32_t a0;	/* SMC function ID */
	uint32_t a1;	/* Parameter */
	uint32_t a2;	/* Parameter */
	uint32_t a3;	/* Thread ID when returning from RPC */
	uint32_t a4;	/* Not used */
	uint32_t a5;	/* Not used */
	uint32_t a6;	/* Not used */
	uint32_t a7;	/* Hypervisor Client ID */
};
#endif /*ARM32*/
#ifdef ARM64
struct thread_smc_args {
	uint64_t a0;	/* SMC function ID */
	uint64_t a1;	/* Parameter */
	uint64_t a2;	/* Parameter */
	uint64_t a3;	/* Thread ID when returning from RPC */
	uint64_t a4;	/* Not used */
	uint64_t a5;	/* Not used */
	uint64_t a6;	/* Not used */
	uint64_t a7;	/* Hypervisor Client ID */
};
#endif /*ARM64*/

#ifdef ARM32
struct thread_abort_regs {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t pad;
	uint32_t spsr;
	uint32_t elr;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t ip;
};
#endif /*ARM32*/
#ifdef ARM64
struct thread_abort_regs {
	uint64_t x0;	/* r0_usr */
	uint64_t x1;	/* r1_usr */
	uint64_t x2;	/* r2_usr */
	uint64_t x3;	/* r3_usr */
	uint64_t x4;	/* r4_usr */
	uint64_t x5;	/* r5_usr */
	uint64_t x6;	/* r6_usr */
	uint64_t x7;	/* r7_usr */
	uint64_t x8;	/* r8_usr */
	uint64_t x9;	/* r9_usr */
	uint64_t x10;	/* r10_usr */
	uint64_t x11;	/* r11_usr */
	uint64_t x12;	/* r12_usr */
	uint64_t x13;	/* r13/sp_usr */
	uint64_t x14;	/* r14/lr_usr */
	uint64_t x15;
	uint64_t x16;
	uint64_t x17;
	uint64_t x18;
	uint64_t x19;
	uint64_t x20;
	uint64_t x21;
	uint64_t x22;
	uint64_t x23;
	uint64_t x24;
	uint64_t x25;
	uint64_t x26;
	uint64_t x27;
	uint64_t x28;
	uint64_t x29;
	uint64_t x30;
	uint64_t elr;
	uint64_t spsr;
	uint64_t sp_el0;
#if defined(CFG_TA_PAUTH) || defined(CFG_CORE_PAUTH)
	uint64_t apiakey_hi;
	uint64_t apiakey_lo;
#endif
};
#endif /*ARM64*/

#ifdef ARM32
struct thread_svc_regs {
	uint32_t spsr;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t lr;
};
#endif /*ARM32*/
#ifdef ARM64
struct thread_svc_regs {
	uint64_t elr;
	uint64_t spsr;
	uint64_t x0;	/* r0_usr */
	uint64_t x1;	/* r1_usr */
	uint64_t x2;	/* r2_usr */
	uint64_t x3;	/* r3_usr */
	uint64_t x4;	/* r4_usr */
	uint64_t x5;	/* r5_usr */
	uint64_t x6;	/* r6_usr */
	uint64_t x7;	/* r7_usr */
	uint64_t x8;	/* r8_usr */
	uint64_t x9;	/* r9_usr */
	uint64_t x10;	/* r10_usr */
	uint64_t x11;	/* r11_usr */
	uint64_t x12;	/* r12_usr */
	uint64_t x13;	/* r13/sp_usr */
	uint64_t x14;	/* r14/lr_usr */
	uint64_t x30;
	uint64_t sp_el0;
#ifdef CFG_SECURE_PARTITION
	uint64_t x15;
	uint64_t x16;
	uint64_t x17;
	uint64_t x18;
	uint64_t x19;
	uint64_t x20;
	uint64_t x21;
	uint64_t x22;
	uint64_t x23;
	uint64_t x24;
	uint64_t x25;
	uint64_t x26;
	uint64_t x27;
	uint64_t x28;
	uint64_t x29;
#endif
#if defined(CFG_TA_PAUTH) || defined(CFG_CORE_PAUTH)
	uint64_t apiakey_hi;
	uint64_t apiakey_lo;
#endif
	uint64_t pad;
} __aligned(16);
#endif /*ARM64*/

#ifdef ARM32
struct thread_ctx_regs {
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t svc_spsr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t pc;
	uint32_t cpsr;
};
#endif /*ARM32*/

#ifdef ARM64
struct thread_ctx_regs {
	uint64_t sp;
	uint64_t pc;
	uint64_t cpsr;
	uint64_t x[31];
	uint64_t tpidr_el0;
#if defined(CFG_TA_PAUTH) || defined(CFG_CORE_PAUTH)
	uint64_t apiakey_hi;
	uint64_t apiakey_lo;
#endif
};
#endif /*ARM64*/

struct user_mode_ctx;

#ifdef CFG_WITH_ARM_TRUSTED_FW
/*
 * These five functions have a __weak default implementation which does
 * nothing. Platforms are expected to override them if needed.
 */
unsigned long thread_cpu_off_handler(unsigned long a0, unsigned long a1);
unsigned long thread_cpu_suspend_handler(unsigned long a0, unsigned long a1);
unsigned long thread_cpu_resume_handler(unsigned long a0, unsigned long a1);
unsigned long thread_system_off_handler(unsigned long a0, unsigned long a1);
unsigned long thread_system_reset_handler(unsigned long a0, unsigned long a1);
#endif /*CFG_WITH_ARM_TRUSTED_FW*/

/*
 * Defines the bits for the exception mask used by the
 * thread_*_exceptions() functions below.
 * These definitions are compatible with both ARM32 and ARM64.
 */
#if defined(CFG_ARM_GICV3)
#define THREAD_EXCP_FOREIGN_INTR	(ARM32_CPSR_F >> ARM32_CPSR_F_SHIFT)
#define THREAD_EXCP_NATIVE_INTR		(ARM32_CPSR_I >> ARM32_CPSR_F_SHIFT)
#else
#define THREAD_EXCP_FOREIGN_INTR	(ARM32_CPSR_I >> ARM32_CPSR_F_SHIFT)
#define THREAD_EXCP_NATIVE_INTR		(ARM32_CPSR_F >> ARM32_CPSR_F_SHIFT)
#endif
#define THREAD_EXCP_ALL			(THREAD_EXCP_FOREIGN_INTR	\
					| THREAD_EXCP_NATIVE_INTR	\
					| (ARM32_CPSR_A >> ARM32_CPSR_F_SHIFT))

#ifdef CFG_WITH_VFP
/*
 * thread_kernel_enable_vfp() - Temporarily enables usage of VFP
 *
 * Foreign interrupts are masked while VFP is enabled. User space must not be
 * entered before thread_kernel_disable_vfp() has been called to disable VFP
 * and restore the foreign interrupt status.
 *
 * This function may only be called from an active thread context and may
 * not be called again before thread_kernel_disable_vfp() has been called.
 *
 * VFP state is saved as needed.
 *
 * Returns a state variable that should be passed to
 * thread_kernel_disable_vfp().
 */
uint32_t thread_kernel_enable_vfp(void);

/*
 * thread_kernel_disable_vfp() - Disables usage of VFP
 * @state:	state variable returned by thread_kernel_enable_vfp()
 *
 * Disables usage of VFP and restores foreign interrupt status after a call to
 * thread_kernel_enable_vfp().
 *
 * This function may only be called after a call to
 * thread_kernel_enable_vfp().
 */
void thread_kernel_disable_vfp(uint32_t state);

/*
 * thread_kernel_save_vfp() - Saves kernel vfp state if enabled
 */
void thread_kernel_save_vfp(void);

/*
 * thread_kernel_save_vfp() - Restores kernel vfp state
 */
void thread_kernel_restore_vfp(void);

/*
 * thread_user_enable_vfp() - Enables vfp for user mode usage
 * @uvfp:	pointer to where to save the vfp state if needed
 */
void thread_user_enable_vfp(struct thread_user_vfp_state *uvfp);
#else /*CFG_WITH_VFP*/
static inline void thread_kernel_save_vfp(void)
{
}

static inline void thread_kernel_restore_vfp(void)
{
}
#endif /*CFG_WITH_VFP*/

/*
 * thread_user_save_vfp() - Saves the user vfp state if enabled
 */
#ifdef CFG_WITH_VFP
void thread_user_save_vfp(void);
#else
static inline void thread_user_save_vfp(void)
{
}
#endif

/*
 * thread_user_clear_vfp() - Clears the vfp state
 * @uctx:	pointer to user mode context containing the saved state to clear
 */
#ifdef CFG_WITH_VFP
void thread_user_clear_vfp(struct user_mode_ctx *uctx);
#else
static inline void thread_user_clear_vfp(struct user_mode_ctx *uctx __unused)
{
}
#endif

#ifdef ARM64
/*
 * thread_get_saved_thread_sp() - Returns the saved sp of current thread
 *
 * When switching from the thread stack pointer the value is stored
 * separately in the current thread context. This function returns this
 * saved value.
 *
 * @returns stack pointer
 */
vaddr_t thread_get_saved_thread_sp(void);
#endif /*ARM64*/

/*
 * Provides addresses and size of kernel code that must be mapped while in
 * user mode.
 */
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
			   vaddr_t *va, size_t *sz);
#else
static inline void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}
#endif

/*
 * Provides addresses and size of kernel (rw) data that must be mapped
 * while in user mode.
 */
#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) && \
	defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
			   vaddr_t *va, size_t *sz);
#else
static inline void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}
#endif

/*
 * Disables and empties the prealloc RPC cache one reference at a time. If
 * all threads are idle this function returns true and a cookie of one shm
 * object which was removed from the cache. When the cache is empty *cookie
 * is set to 0 and the cache is disabled else a valid cookie value. If one
 * thread isn't idle this function returns false.
 */
bool thread_disable_prealloc_rpc_cache(uint64_t *cookie);

/*
 * Enabled the prealloc RPC cache. If all threads are idle the cache is
 * enabled and this function returns true. If one thread isn't idle this
 * function return false.
 */
bool thread_enable_prealloc_rpc_cache(void);

unsigned long thread_smc(unsigned long func_id, unsigned long a1,
			 unsigned long a2, unsigned long a3);
void thread_smccc(struct thread_smc_args *arg_res);
#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_ARCH_H*/
