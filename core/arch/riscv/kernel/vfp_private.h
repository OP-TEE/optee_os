/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef VFP_PRIVATE
#define VFP_PRIVATE

#include <kernel/vfp.h>

void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]);
void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]);
void vfp_clear_extension_regs(void);

#if defined(CFG_RISCV_ISA_V)
/* Header plus 32 * vlenb, the size to allocate for a vector context */
size_t riscv_vector_state_size(void);

/* The unit must be enabled by the caller; xstatus is left as found. */
void vfp_save_vector_regs(struct riscv_vector_state *state);
void vfp_restore_vector_regs(const struct riscv_vector_state *state);

/* Zero v0..v31 and vcsr in place; the unit must be enabled by the caller. */
void vfp_clear_vector_regs(void);
#endif

#endif /*VFP_PRIVATE*/
