// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <assert.h>
#include <kernel/panic.h>
#include <kernel/vfp.h>
#include <malloc.h>
#include <riscv.h>
#include <string.h>
#include <trace.h>
#include "vfp_private.h"

/* The units currently enabled in xstatus (field not Off) */
static uint32_t enabled_units(void)
{
	return read_csr(CSR_XSTATUS) & VFP_UNIT_ALL;
}

/* Enable @units, setting their fields to Dirty */
static void enable_units(uint32_t units)
{
	set_csr(CSR_XSTATUS, units);
}

/* Disable @units, clearing their fields to Off */
static void disable_units(uint32_t units)
{
	clear_csr(CSR_XSTATUS, units);
}

bool vfp_is_enabled(void)
{
	return enabled_units() != 0;
}

void vfp_enable(void)
{
	/* The core takes all units; the caller saved any live owner first. */
	enable_units(VFP_UNIT_ALL);
}

void vfp_enable_fault_unit(void)
{
	enable_units(vfp_fault_unit());
}

void vfp_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VFP_MASK);
}

uint32_t vfp_fault_unit(void)
{
	uint32_t on = enabled_units();

	if (!(on & VFP_UNIT_FP))
		return VFP_UNIT_FP;
#if defined(CFG_RISCV_ISA_V)
	if (!(on & VFP_UNIT_VEC))
		return VFP_UNIT_VEC;
#endif
	return 0;
}

uint32_t vfp_state_units(struct vfp_state *state)
{
	uint32_t units = state->xstatus & VFP_UNIT_ALL;

#if defined(CFG_RISCV_ISA_V)
	/* A saved vector field only counts with a context to restore. */
	if (!state->vregs)
		units &= ~VFP_UNIT_VEC;
#endif
	return units;
}

void vfp_clear_unit_regs(uint32_t units)
{
	if (units & VFP_UNIT_FP)
		vfp_clear_extension_regs();
#if defined(CFG_RISCV_ISA_V)
	if (units & VFP_UNIT_VEC)
		vfp_clear_vector_regs();
#endif
}

uint32_t vfp_lazy_save(struct vfp_state *state, uint32_t units, bool force)
{
	uint32_t saved = 0;

	if ((units & VFP_UNIT_FP) &&
	    (force || (state->xstatus & CSR_XSTATUS_FS_MASK))) {
		assert(!(enabled_units() & VFP_UNIT_FP));
		enable_units(VFP_UNIT_FP);
		state->fcsr = read_csr(CSR_FCSR);
		vfp_save_extension_regs(state->reg);
		disable_units(VFP_UNIT_FP);
		saved |= VFP_UNIT_FP;
	}
#if defined(CFG_RISCV_ISA_V)
	if ((units & VFP_UNIT_VEC) && state->vregs &&
	    (force || (state->xstatus & CSR_XSTATUS_VS_MASK))) {
		assert(!(enabled_units() & VFP_UNIT_VEC));
		enable_units(VFP_UNIT_VEC);
		vfp_save_vector_regs(state->vregs);
		disable_units(VFP_UNIT_VEC);
		saved |= VFP_UNIT_VEC;
	}
#endif
	return saved;
}

#if defined(CFG_RISCV_ISA_V)
/*
 * The vector context size, set from vlenb by the first allocation, at boot
 * once check_build_isa() has confirmed V. Every hart must share it.
 */
static size_t vec_ctx_size;

void vfp_init_per_cpu(void)
{
	if (vec_ctx_size && riscv_vector_state_size() != vec_ctx_size)
		panic("vector register width differs between harts");
}

bool vfp_alloc_vector_context(struct vfp_state *state)
{
	if (state->vregs)
		return true;

	if (!vec_ctx_size) {
		vec_ctx_size = riscv_vector_state_size();
		DMSG("Vector context switching enabled, %zu bytes a context",
		     vec_ctx_size);
	}

	state->vregs = memalign(__alignof__(long), vec_ctx_size);
	if (!state->vregs)
		return false;

	memset(state->vregs, 0, vec_ctx_size);
	return true;
}

void vfp_free_vector_context(struct vfp_state *state)
{
	free(state->vregs);
	state->vregs = NULL;
}
#endif

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	/*
	 * Capture the enabled units' fields and disable them. The registers are
	 * left in place, to be saved by vfp_lazy_save() if they turn out to be
	 * needed.
	 */
	state->xstatus = read_csr(CSR_XSTATUS) & CSR_XSTATUS_VFP_MASK;
	vfp_disable();
}

void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save)
{
	/* Each unit is saved only if its owner left it in use. */
	vfp_lazy_save(state, VFP_UNIT_ALL, force_save);
}

void vfp_lazy_restore_state(struct vfp_state *state, uint32_t units)
{
	/*
	 * @units, not the saved fields, says what was saved: a force-saved
	 * unit may have had its field Off. The fields are then set back to the
	 * owner's.
	 */
	if (units & VFP_UNIT_FP) {
		enable_units(VFP_UNIT_FP);
		write_csr(CSR_FCSR, state->fcsr);
		vfp_restore_extension_regs(state->reg);
	}
#if defined(CFG_RISCV_ISA_V)
	if (units & VFP_UNIT_VEC) {
		enable_units(VFP_UNIT_VEC);
		vfp_restore_vector_regs(state->vregs);
	}
#endif
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VFP_MASK);
	set_csr(CSR_XSTATUS, state->xstatus);
}
