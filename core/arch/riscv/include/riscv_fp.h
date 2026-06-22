/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __KERNEL_RISCV_FP_H
#define __KERNEL_RISCV_FP_H

#ifndef __ASSEMBLER__

#include <types_ext.h>
#include <compiler.h>

/* Floating-Point Context Struct */
struct riscv_fp_state {
#if RISCV_XLEN_BITS == 64
	uint64_t fpregs[32];
#elif RISCV_XLEN_BITS == 32
	uint32_t fpregs[32];
#endif
	unsigned long fcsr;
};

void riscv_save_fp_state(struct riscv_fp_state *dst);
void riscv_restore_fp_state(struct riscv_fp_state *src);
#endif /* !__ASSEMBLER__ */
#endif /* __KERNEL_RISCV_FP_H */

