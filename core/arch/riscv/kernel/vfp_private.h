/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef VFP_PRIVATE
#define VFP_PRIVATE

#include <kernel/vfp.h>

#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
/* Header plus 32 * vlenb, the size to allocate for a vector context */
size_t riscv_vector_state_size(void);

/* The unit must be enabled by the caller; xstatus is left as found. */
void riscv_vector_save(struct riscv_vector_state *state);
void riscv_vector_restore(const struct riscv_vector_state *state);
#endif

#endif /*VFP_PRIVATE*/
