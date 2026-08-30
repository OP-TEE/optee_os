/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __RISCV_FP_H
#define __RISCV_FP_H

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <riscv.h>
#include <types_ext.h>

/*
 * struct riscv_fp_state - floating-point register context
 * @fpregs:	f0..f31, each RISCV_FLEN_BITS wide
 * @fcsr:	floating-point control and status register
 *
 * The layout is shared with riscv_fp.S, see RISCV_FP_FCSR_OFF.
 */
struct riscv_fp_state {
#if defined(__riscv_flen) && __riscv_flen == 64
	uint64_t fpregs[32];
#elif defined(__riscv_flen) && __riscv_flen == 32
	uint32_t fpregs[32];
#endif
	uint32_t fcsr;
};

/*
 * riscv_save_fp_state() - save f0..f31 and fcsr into @state
 * riscv_restore_fp_state() - load f0..f31 and fcsr from @state
 *
 * Both enable the floating-point unit for the duration of the transfer and
 * leave xstatus.FS as they found it, so they can be called with the FP unit
 * disabled without disturbing the caller's view of xstatus.
 */
void riscv_save_fp_state(struct riscv_fp_state *state);
void riscv_restore_fp_state(struct riscv_fp_state *state);

#endif /* !__ASSEMBLER__ */
#endif /* __RISCV_FP_H */
