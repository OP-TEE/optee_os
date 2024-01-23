/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 * Copyright (c) 2023 Andes Technology Corporation
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <riscv.h>
#include <riscv_macros.S>
#include <sbi.h>
#include <tee/optee_abi.h>
#include <tee/teeabi_opteed.h>
#include <tee/teeabi_opteed_macros.h>

/*
 * Implement based on the transport method used to communicate between
 * untrusted domain and trusted domain. It could be an SBI/ECALL-based to
 * a security monitor running in M-Mode and panic or messaging-based across
 * domains where we return to a messaging callback which parses and handles
 * messages.
 *
 * void thread_return_to_udomain(unsigned long arg0, unsigned long arg1,
 *                               unsigned long arg2, unsigned long arg3,
 *                               unsigned long arg4, unsigned long arg5);
 */
FUNC thread_return_to_udomain , :
	/* Caller should provide arguments in a0~a5 */
#if defined(CFG_RISCV_WITH_M_MODE_SM)
	li	a7, SBI_EXT_TEE		/* extension ID */
	li	a6, 0			/* function ID (unused) */
	ecall
#else
	/* Other protocol */
#endif
	/* ABI to REE should not return */
	panic_at_abi_return
END_FUNC thread_return_to_udomain

FUNC thread_std_abi_entry , :
	jal	__thread_std_abi_entry

	/* Save return value */
	mv	s0, a0

	/* Disable all interrupts */
	csrc	CSR_XSTATUS, CSR_XSTATUS_IE

	/* Switch to temporary stack */
	jal	thread_get_tmp_sp
	mv	sp, a0

	/*
	 * We are returning from thread_alloc_and_run()
	 * set thread state as free
	 */
	jal	thread_state_free

	/* Restore __thread_std_abi_entry() return value */
	mv	a1, s0
	li	a2, 0
	li	a3, 0
	li	a4, 0
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE

	/* Return to untrusted domain */
	jal	thread_return_to_udomain
END_FUNC thread_std_abi_entry

/*
 * void thread_rpc_xstatus(uint32_t rv[THREAD_RPC_NUM_ARGS],
 *                         unsigned long status);
 */
FUNC thread_rpc_xstatus , :
	 /* Use stack for temporary storage */
	addi	sp, sp, -REGOFF(8)

	/* Read xSTATUS */
	csrr	a2, CSR_XSTATUS

	/* Mask all maskable exceptions before switching to temporary stack */
	csrw	CSR_XIE, x0

	/* Save return address xSTATUS and pointer to rv */
	STR	a0, REGOFF(0)(sp)
	STR	a1, REGOFF(1)(sp)
	STR	s0, REGOFF(2)(sp)
	STR	ra, REGOFF(3)(sp)
	STR	a2, REGOFF(4)(sp)
#ifdef CFG_UNWIND
	addi	s0, sp, REGOFF(8)
#endif

	/* Save thread state */
	jal	thread_get_ctx_regs
	LDR	ra, REGOFF(3)(sp)
	/* Save ra, sp, gp, tp, and s0~s11 */
	store_xregs a0, THREAD_CTX_REG_RA, REG_RA, REG_TP
	store_xregs a0, THREAD_CTX_REG_S0, REG_S0, REG_S1
	store_xregs a0, THREAD_CTX_REG_S2, REG_S2, REG_S11

	/* Get to tmp stack */
	jal	thread_get_tmp_sp

	/* Get pointer to rv */
	LDR	s1, REGOFF(0)(sp)

	/* xSTATUS to restore */
	LDR	a1, REGOFF(1)(sp)
	/* Switch to tmp stack */
	mv	sp, a0

	/* Early load rv[] into s2-s4 */
	lw	s2, 0(s1)
	lw	s3, 4(s1)
	lw	s4, 8(s1)

	li	a0, THREAD_FLAGS_COPY_ARGS_ON_RETURN
	la	a2, .thread_rpc_return
	jal	thread_state_suspend

	mv	a4, a0	/* thread index */
	mv	a1, s2	/* rv[0] */
	mv	a2, s3	/* rv[1] */
	mv	a3, s4	/* rv[2] */
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE

	/* Return to untrusted domain */
	jal	thread_return_to_udomain
.thread_rpc_return:
	/*
	 * Jumps here from thread_resume() above when RPC has returned.
	 * At this point has the stack pointer been restored to the value
	 * stored in THREAD_CTX above.
	 */

	/* Get pointer to rv[] */
	LDR	a4, REGOFF(0)(sp)

	/* Store a0-a3 into rv[] */
	sw	a0, 0(a4)
	sw	a1, 4(a4)
	sw	a2, 8(a4)
	sw	a3, 12(a4)

	/* Pop saved XSTATUS from stack */
	LDR	s0, REGOFF(4)(sp)
	csrw	CSR_XSTATUS, s0

	/* Pop s0 from stack */
	LDR	s0, REGOFF(2)(sp)

	addi	sp, sp, REGOFF(8)
	ret
END_FUNC thread_rpc_xstatus
DECLARE_KEEP_PAGER thread_rpc_xstatus

LOCAL_FUNC vector_std_abi_entry, : , .identity_map
	jal	thread_handle_std_abi
	/*
	 * Normally thread_handle_std_abi() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_abi()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	/* Restore thread_handle_std_abi() return value */
	mv	a1, a0
	li	a2, 0
	li	a3, 0
	li	a4, 0
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE

	/* Return to untrusted domain */
	j	thread_return_to_udomain
END_FUNC vector_std_abi_entry

LOCAL_FUNC vector_fast_abi_entry , : , .identity_map
	addi    sp, sp, -THREAD_ABI_ARGS_SIZE
	store_xregs sp, THREAD_ABI_ARGS_A0, REG_A0, REG_A7
	mv      a0, sp
	jal	thread_handle_fast_abi
	load_xregs sp, THREAD_ABI_ARGS_A0, REG_A1, REG_A7
	addi    sp, sp, THREAD_ABI_ARGS_SIZE

	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE
	/* Return to untrusted domain */
	j	thread_return_to_udomain
END_FUNC vector_fast_abi_entry

LOCAL_FUNC vector_fiq_entry , : , .identity_map
	/* Secure Monitor received a FIQ and passed control to us. */
	jal	interrupt_main_handler

	li	a0, TEEABI_OPTEED_RETURN_FIQ_DONE
	/* Return to untrusted domain */
	j	thread_return_to_udomain
END_FUNC vector_fiq_entry

/*
 * Vector table supplied to M-mode secure monitor (e.g., openSBI) at
 * initialization.
 *
 * Note that M-mode secure monitor depends on the layout of this vector table,
 * any change in layout has to be synced with M-mode secure monitor.
 */
FUNC thread_vector_table , : , .identity_map, , nobti
	.option push
	.option norvc
	j   vector_std_abi_entry
	j   vector_fast_abi_entry
	j   .
	j   .
	j   .
	j   .
	j   vector_fiq_entry
	j   .
	j   .
	.option pop
END_FUNC thread_vector_table
DECLARE_KEEP_PAGER thread_vector_table
