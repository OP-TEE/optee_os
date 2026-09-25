/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __KERNEL_VFP_H
#define __KERNEL_VFP_H

#include <compiler.h>
#include <types_ext.h>

/*
 * On RISC-V the generic vfp hooks drive the vector unit. There is no separate
 * scalar floating-point context switching here: it is a separate series. When
 * the core is built for the vector ISA (CFG_RISCV_VEC) and CFG_WITH_VFP is
 * set, the state below and the routines carry the vector registers.
 */
#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
/*
 * The vector CSRs plus the register file. vl and vtype are read-only CSRs
 * restored through vsetvl; they must be carried too or a concurrent TA's
 * vsetvl leaves the resumed context with the wrong vl/vtype. The register
 * area is sized at runtime from vlenb (32 * vlenb), so the struct is
 * allocated rather than embedded.
 */
struct riscv_vector_state {
	unsigned long vcsr;
	unsigned long vstart;
	unsigned long vl;
	unsigned long vtype;
	uint8_t vregs[];
};
#endif

struct vfp_state {
#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
	/* Vector context, allocated by the thread layer, and xstatus.VS */
	struct riscv_vector_state *vregs;
	unsigned long vs;
#endif
};

#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
bool vfp_is_enabled(void);
void vfp_enable(void);
void vfp_disable(void);
#else
static inline bool vfp_is_enabled(void)
{
	return false;
}

static inline void vfp_enable(void)
{
}

static inline void vfp_disable(void)
{
}
#endif

void vfp_lazy_save_state_init(struct vfp_state *state);
void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save);
void vfp_lazy_restore_state(struct vfp_state *state, bool full_state);

#endif /*__KERNEL_VFP_H*/
