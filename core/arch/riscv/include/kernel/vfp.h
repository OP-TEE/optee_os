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

#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_ISA_V)
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
#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_ISA_V)
	/* Vector context, allocated by the thread layer, and xstatus.VS */
	struct riscv_vector_state *vregs;
	unsigned long vs;
#endif
};

#ifdef CFG_WITH_VFP
/*
 * vfp_is_enabled() - True when every FP/vector unit the build has is enabled:
 *		      xstatus.FS, and xstatus.VS under CFG_RISCV_ISA_V
 */
bool vfp_is_enabled(void);

/*
 * vfp_enable() - Enable the next unit still Off: the FP unit (xstatus.FS)
 *		  first, then the vector unit (xstatus.VS) once FP is on
 *
 * One call brings out one unit, so a repeated disabled-unit trap walks FP
 * then vector and a TA that only uses FP never enables the vector unit.
 */
void vfp_enable(void);

/*
 * vfp_disable() - Disable every unit, FS and VS together in one write
 */
void vfp_disable(void);

/*
 * vfp_in_use() - True when any FP/vector unit the build has is enabled
 *		  (xstatus.FS, or xstatus.VS under CFG_RISCV_ISA_V)
 */
bool vfp_in_use(void);

#if defined(CFG_RISCV_ISA_V)
/*
 * vfp_fault_is_vector() - True when the current disabled-unit trap is for the
 *			   vector unit (FP is already on, so vector is next)
 */
bool vfp_fault_is_vector(void);
#endif
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

static inline bool vfp_in_use(void)
{
	return false;
}
#endif

/*
 * vfp_lazy_save_state_init() - Captures FS/VS and disables the enabled units
 * @state:	FP/vector state to initialise
 *
 * The registers themselves are left in place, to be saved per unit by
 * vfp_lazy_save_fp()/vfp_lazy_save_vec() if they turn out to be needed.
 */
void vfp_lazy_save_state_init(struct vfp_state *state);

/*
 * vfp_lazy_save_fp() - Saves the FP registers if the FP unit was in use
 * @state:	FP/vector state to save to
 * @force:	Saves even if FS was Off at vfp_lazy_save_state_init()
 *
 * Returns true if the registers were saved.
 */
bool vfp_lazy_save_fp(struct vfp_state *state, bool force);

#if defined(CFG_RISCV_ISA_V)
/*
 * vfp_lazy_save_vec() - Saves the vector registers if the unit was in use
 * @state:	FP/vector state to save to
 * @force:	Saves even if VS was Off at vfp_lazy_save_state_init()
 *
 * Returns true if the registers were saved.
 */
bool vfp_lazy_save_vec(struct vfp_state *state, bool force);
#endif

/*
 * vfp_lazy_save_state_final() - Saves whichever units their owner left in use
 * @state:	FP/vector state to save to
 * @force_save:	Forces the save even if a unit was disabled at
 *		vfp_lazy_save_state_init()
 */
void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save);

/*
 * vfp_lazy_restore_state() - Restores the saved units and FS/VS
 * @state:	FP/vector state to restore
 * @restore_fp:	Restore the FP registers (they were saved)
 * @restore_vec: Restore the vector registers (they were saved)
 */
void vfp_lazy_restore_state(struct vfp_state *state, bool restore_fp,
			    bool restore_vec);

#endif /*__KERNEL_VFP_H*/
