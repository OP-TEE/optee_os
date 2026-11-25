/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __KERNEL_VFP_H
#define __KERNEL_VFP_H

#include <compiler.h>
#include <riscv.h>
#include <types_ext.h>

#define VFP_NUM_REGS	U(32)

/*
 * The units as a bitmask, each unit being its xstatus field, so a unit mask
 * can be used directly with the xstatus CSR.
 */
#define VFP_UNIT_FP	CSR_XSTATUS_FS_MASK
#define VFP_UNIT_ALL	VFP_UNIT_FP

#if defined(__riscv_flen) && __riscv_flen == 32
struct vfp_reg {
	uint32_t v;
};
#else
struct vfp_reg {
	uint64_t v;
};
#endif

#if defined(CFG_RISCV_ISA_V)
/*
 * A vector context: the vector CSRs followed by v0-v31, whose size
 * (32 * vlenb) is only known at runtime.
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
#if defined(CFG_RISCV_ISA_V)
	/* Vector context, from vfp_alloc_vector_context() */
	struct riscv_vector_state *vregs;
#endif
	/* The units' xstatus fields at vfp_lazy_save_state_init() */
	unsigned long xstatus;
};

#ifdef CFG_WITH_VFP
/*
 * vfp_is_enabled() - True as soon as any unit is enabled
 */
bool vfp_is_enabled(void);

/*
 * vfp_enable() - Enable every unit, for use by the core itself
 *
 * The caller must have saved any live owner state first.
 */
void vfp_enable(void);

/*
 * vfp_enable_fault_unit() - Enable the unit returned by vfp_fault_unit()
 */
void vfp_enable_fault_unit(void);

/*
 * vfp_disable() - Disable every unit, in one write
 */
void vfp_disable(void);

/*
 * vfp_fault_unit() - The single unit to hand over on a disabled-unit trap:
 *		      the first one still Off; 0 if all on
 */
uint32_t vfp_fault_unit(void);
#else
static inline bool vfp_is_enabled(void)
{
	return false;
}

static inline void vfp_enable(void)
{
}

static inline void vfp_enable_fault_unit(void)
{
}

static inline void vfp_disable(void)
{
}
#endif

/*
 * vfp_lazy_save_state_init() - Captures the units' fields and disables them
 * @state:	FP state to initialise
 *
 * The registers themselves are left in place, to be saved by vfp_lazy_save()
 * if they turn out to be needed.
 */
void vfp_lazy_save_state_init(struct vfp_state *state);

/*
 * vfp_lazy_save() - Save the registers of the requested units that were in use
 * @state:	FP state to save to
 * @units:	Units to consider (VFP_UNIT_*)
 * @force:	Save even if a unit's field was Off at the save-init call
 *
 * Returns the mask of units actually saved.
 */
uint32_t vfp_lazy_save(struct vfp_state *state, uint32_t units, bool force);

/*
 * vfp_state_units() - Units a saved state had in use: field not Off
 */
uint32_t vfp_state_units(struct vfp_state *state);

/*
 * vfp_clear_unit_regs() - Zero the live registers of the given units
 * @units:	Units to clear; each must already be enabled by the caller
 */
void vfp_clear_unit_regs(uint32_t units);

#if defined(CFG_RISCV_ISA_V)
/*
 * vfp_init_per_cpu() - Per-hart init: once the vector context size is set by
 *			the first allocation, panic if this hart's vlenb differs
 */
void vfp_init_per_cpu(void);

/*
 * vfp_alloc_vector_context() - Give @state a zeroed vector context if it has
 *				none; the first call sets the size from vlenb
 *
 * Returns false on allocation failure.
 */
bool vfp_alloc_vector_context(struct vfp_state *state);

/*
 * vfp_free_vector_context() - Free @state's vector context, if any
 */
void vfp_free_vector_context(struct vfp_state *state);
#else
static inline void vfp_init_per_cpu(void)
{
}

static inline bool vfp_alloc_vector_context(struct vfp_state *state __unused)
{
	return true;
}

static inline void vfp_free_vector_context(struct vfp_state *state __unused)
{
}
#endif

/*
 * vfp_lazy_save_state_final() - Saves whichever units their owner left in use
 * @state:	FP state to save to
 * @force_save:	Forces the save even if a unit was disabled at
 *		vfp_lazy_save_state_init()
 */
void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save);

/*
 * vfp_lazy_restore_state() - Restore the given units' registers and fields
 * @state:	FP state to restore
 * @units:	Units whose registers were saved and are to be restored
 */
void vfp_lazy_restore_state(struct vfp_state *state, uint32_t units);

#endif /*__KERNEL_VFP_H*/
