/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __KERNEL_VFP_H
#define __KERNEL_VFP_H

#include <compiler.h>
#include <types_ext.h>

#define VFP_NUM_REGS	U(32)

#if defined(__riscv_flen) && __riscv_flen == 32
struct vfp_reg {
	uint32_t v;
};
#else
struct vfp_reg {
	uint64_t v;
};
#endif

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
	struct vfp_reg reg[VFP_NUM_REGS];
	uint32_t fcsr;
	/* xstatus.FS at the time of vfp_lazy_save_state_init() */
	unsigned long fs;
#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
	/* Vector context, allocated by the thread layer, and xstatus.VS */
	struct riscv_vector_state *vregs;
	unsigned long vs;
#endif
};

#ifdef CFG_WITH_VFP
/*
 * vfp_is_enabled() - Returns true if the FP unit is enabled
 */
bool vfp_is_enabled(void);

/*
 * vfp_enable() - Enables the FP unit by taking xstatus.FS out of Off
 */
void vfp_enable(void);

/*
 * vfp_disable() - Disables the FP unit by setting xstatus.FS to Off
 */
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

/*
 * vfp_lazy_save_state_init() - Saves FS and disables the FP unit
 * @state:	FP state to initialise
 *
 * The registers themselves are left in place, to be saved by
 * vfp_lazy_save_state_final() if they turn out to be needed.
 */
void vfp_lazy_save_state_init(struct vfp_state *state);

/*
 * vfp_lazy_save_state_final() - Saves the FP registers
 * @state:	FP state to save to
 * @force_save:	Forces the save even if the unit was disabled at
 *		vfp_lazy_save_state_init()
 */
void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save);

/*
 * vfp_lazy_restore_state() - Restores FP state
 * @state:	FP state to restore
 * @full_state:	If the registers should be restored too, false if they were
 *		never touched and only FS has to be put back
 */
void vfp_lazy_restore_state(struct vfp_state *state, bool full_state);

#endif /*__KERNEL_VFP_H*/
