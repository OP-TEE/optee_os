/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <asm.S>
#include <riscv.h>

#define DETECT_OP_CSRR		0
#define DETECT_OP_CSRRW		1

.macro save_and_disable_xie reg
	csrrw	\reg, CSR_XIE, zero
.endm

.macro restore_xie reg
	csrw	CSR_XIE, \reg
.endm

.macro save_and_replace_xtvec reg, label
	la	\reg, \label
	csrrw	\reg, CSR_XTVEC, \reg
.endm

.macro restore_xtvec reg
	csrw	CSR_XTVEC, \reg
.endm

/**
 * @brief A temporary trap handler to handle an exception during csr detection.
 *        If csr read/write instruction leads to a trap, CPU will enter this
 *        function and XRET with a0 = 0, which means the csr is not detected.
 *        The caller must expect that a0 is used in this function.
 */
FUNC csr_detect_trap_vect , :
	csrr	a0, CSR_XEPC
	addi	a0, a0, 4
	csrw	CSR_XEPC, a0
	mv	a0, zero
	XRET
END_FUNC csr_detect_trap_vect

/* Detect CSR by csrr/csrrw instruction. a0=1 if detected, otherwise a0=0 */
.macro detect_csr csr, op, reg0, reg1, reg2
	addi	a0, a0, 1
	save_and_disable_xie \reg0
	save_and_replace_xtvec \reg1, csr_detect_trap_vect
.if \op == DETECT_OP_CSRR
	csrr	\reg2, \csr
.elseif \op == DETECT_OP_CSRRW
	csrrw	\reg2, \csr, zero
.endif
	restore_xtvec \reg1
	restore_xie \reg0
.endm

.macro detect_csr_by_csrr csr, reg0, reg1, reg2
	detect_csr \csr, DETECT_OP_CSRR, \reg0, \reg1, \reg2
.endm

.macro detect_csr_by_csrrw csr, reg0, reg1, reg2
	detect_csr \csr, DETECT_OP_CSRRW, \reg0, \reg1, \reg2
.endm

/**
 * bool riscv_detect_csr_seed(void);
 * @brief A helper function to detect if CSR seed is accessible. The value of a0
 *        will be cleared by csr_detect_trap_vect() if exception occurs.
 * @retval 1 if CSR seed is detected, otherwise 0
 */
FUNC riscv_detect_csr_seed , :
	detect_csr_by_csrrw seed, a1, a2, a3
	ret
END_FUNC riscv_detect_csr_seed
