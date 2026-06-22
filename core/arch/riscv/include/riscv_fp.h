/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __RISCV_FP_H
#define __RISCV_FP_H

#ifndef __ASSEMBLER__

#include <types_ext.h>
#include <compiler.h>
#include <riscv.h>

/* Floating-Point Context Struct */
struct riscv_fp_state {
#if RISCV_FLEN_BITS == 64
	uint64_t fpregs[32];
#elif RISCV_FLEN_BITS == 32
	uint32_t fpregs[32];
#endif
	uint32_t fcsr;
};

void riscv_save_fp_state(struct riscv_fp_state *dst);
void riscv_restore_fp_state(struct riscv_fp_state *src);

void riscv_fp_test_load_pattern(void);
void riscv_fp_test_clear(void);

#endif /* !__ASSEMBLER__ */
#endif /* __RISCV_FP_H */

