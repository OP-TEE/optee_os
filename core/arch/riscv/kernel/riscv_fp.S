/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv.h>
#include <riscv_macros.S>
#include <riscv_fp.h>

/* void riscv_save_fp_state(struct riscv_fp_state *dst) */
FUNC riscv_save_fp_state , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_FS_MASK
	csrs	CSR_XSTATUS, t0

	store_fpregs a0, 0, 0, 31

	csrr	t0, fcsr
	STR	t0, RISCV_FP_FCSR_OFF(a0)

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC riscv_save_fp_state


/* void riscv_restore_fp_state(struct riscv_fp_state *src) */
FUNC riscv_restore_fp_state , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_FS_MASK
	csrs	CSR_XSTATUS, t0

	load_fpregs a0, 0, 0, 31

	LDR	t0, RISCV_FP_FCSR_OFF(a0)
	csrw	fcsr, t0

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC riscv_restore_fp_state
