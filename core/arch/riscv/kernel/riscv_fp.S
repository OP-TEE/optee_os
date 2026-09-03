/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <riscv.h>
#include <riscv_fp.h>
#include <riscv_macros.S>

/*
 * void riscv_save_fp_state(struct riscv_fp_state *state)
 *
 * Saves f0..f31 and fcsr. The floating-point unit is enabled for the
 * duration of the transfer and xstatus is written back unmodified before
 * returning, so the caller's FS state is preserved.
 */
FUNC riscv_save_fp_state , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_FS_MASK
	csrs	CSR_XSTATUS, t0

	store_fpregs a0, 0, 0, 31

	frcsr	t0
	sw	t0, RISCV_FP_FCSR_OFF(a0)

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC riscv_save_fp_state

/*
 * void riscv_restore_fp_state(struct riscv_fp_state *state)
 *
 * Loads f0..f31 and fcsr. Enables and restores xstatus as above.
 */
FUNC riscv_restore_fp_state , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_FS_MASK
	csrs	CSR_XSTATUS, t0

	load_fpregs a0, 0, 0, 31

	lw	t0, RISCV_FP_FCSR_OFF(a0)
	fscsr	t0

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC riscv_restore_fp_state
