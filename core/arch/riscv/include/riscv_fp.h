/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Limited
 */

#ifndef __KERNEL_RISCV_FP_H
#define __KERNEL_RISCV_FP_H

#include <types_ext.h>
#include <compiler.h>

/* CSR Status Bit Masks for Floating-Point Extensions */
#define SSTATUS_FS_MASK       SHIFT_U32(3, 13)  /* bits [14:13] */
#define SSTATUS_FS_OFF        SHIFT_U32(0, 13)
#define SSTATUS_FS_INITIAL    SHIFT_U32(1, 13)
#define SSTATUS_FS_CLEAN      SHIFT_U32(2, 13)
#define SSTATUS_FS_DIRTY      SHIFT_U32(3, 13)

/* Floating-Point Context Struct */
struct riscv_fp_state {
#if __riscv_xlen == 64
	uint64_t fpregs[32];
#elif __riscv_xlen == 32
	uint32_t fpregs[32];
#endif
	unsigned long fcsr;
};

#endif /* __KERNEL_RISCV_FP_H */

