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
	/*
	 *  1. Read original sstatus and temporarily force FS bits to an active
	 *     state.
	 */
	csrr    t1, sstatus
	li      t0, SSTATUS_FS
	csrs    sstatus, t0  /* Set FS bits so FPU instructions do not trap */

#if RISCV_XLEN_BITS == 64
	/* 2. Save data registers at offset 0 (8 bytes per register) */
	store_fpregs fsd, 8, a0, 0, 0, 31

	/* 3. Save Control Register */
	csrr    t0, fcsr
	sd      t0, 256(a0)             /* Offset 256: fcsr */
#else
	/* 2. Save data registers at offset 0 (4 bytes per register) */
	store_fpregs fsw, 4, a0, 0, 0, 31

	/* 3. Save Control Register */
	csrr    t0, fcsr
	sw      t0, 128(a0)             /* Offset 128: fcsr */
#endif
	/* 4. Restore original sstatus LAST to preserve its entry state */
	csrw    sstatus, t1
	ret
END_FUNC riscv_save_fp_state


/* void riscv_restore_fp_state(struct riscv_fp_state *src) */
FUNC riscv_restore_fp_state , :
	/*
	 *  1. Read original sstatus and temporarily force FS bits to an active
	 *     state.
	 */
	csrr    t1, sstatus
	li      t0, SSTATUS_FS
	csrs    sstatus, t0  /* Set FS bits so FPU instructions do not trap */

#if RISCV_XLEN_BITS == 64
	/* 2. Load data registers from structure */
	load_fpregs fld, 8, a0, 0, 0, 31

	/* 3. Load control data register */
	ld      t0, 256(a0)
	csrw    fcsr, t0
#else
	/* 2. Load data registers from structure */
	load_fpregs flw, 4, a0, 0, 0, 31

	/* 3. Load control data register */
	lw      t0, 128(a0)
	csrw    fcsr, t0
#endif

	/* 4. Restore original sstatus LAST */
	csrw    sstatus, t1
	ret
END_FUNC riscv_restore_fp_state
