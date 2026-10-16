// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <assert.h>
#include <kernel/vfp.h>
#include <riscv.h>
#include "vfp_private.h"

static unsigned long read_fs(void)
{
	return (read_csr(CSR_XSTATUS) & CSR_XSTATUS_FS_MASK) >>
	       CSR_XSTATUS_FS_SHIFT;
}

static void write_fs(unsigned long fs)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_FS_MASK);
	set_csr(CSR_XSTATUS, SHIFT_U32(fs, CSR_XSTATUS_FS_SHIFT));
}

static bool fp_is_enabled(void)
{
	return read_fs() != CSR_XSTATUS_FS_OFF;
}

static void fp_enable(void)
{
	set_csr(CSR_XSTATUS, CSR_XSTATUS_FS_MASK);
}

static void fp_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_FS_MASK);
}

#if defined(CFG_RISCV_ISA_V)
static unsigned long read_vs(void)
{
	return (read_csr(CSR_XSTATUS) & CSR_XSTATUS_VS_MASK) >>
	       CSR_XSTATUS_VS_SHIFT;
}

static void write_vs(unsigned long vs)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
	set_csr(CSR_XSTATUS, SHIFT_U32(vs, CSR_XSTATUS_VS_SHIFT));
}

static bool vec_is_enabled(void)
{
	return read_vs() != CSR_XSTATUS_VS_OFF;
}

static void vec_enable(void)
{
	set_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
}

static void vec_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
}
#endif

bool vfp_is_enabled(void)
{
	if (!fp_is_enabled())
		return false;
#if defined(CFG_RISCV_ISA_V)
	if (!vec_is_enabled())
		return false;
#endif
	return true;
}

void vfp_enable(void)
{
	/*
	 * Progressive hand-over: bring out the first unit still Off. FP goes
	 * first; once FS is on, the only unit a disabled-unit trap can still be
	 * about is vector.
	 */
	if (!fp_is_enabled()) {
		fp_enable();
		return;
	}
#if defined(CFG_RISCV_ISA_V)
	if (!vec_is_enabled())
		vec_enable();
#endif
}

void vfp_disable(void)
{
	unsigned long mask = CSR_XSTATUS_FS_MASK;

#if defined(CFG_RISCV_ISA_V)
	mask |= CSR_XSTATUS_VS_MASK;
#endif
	clear_csr(CSR_XSTATUS, mask);
}

bool vfp_in_use(void)
{
	if (fp_is_enabled())
		return true;
#if defined(CFG_RISCV_ISA_V)
	if (vec_is_enabled())
		return true;
#endif
	return false;
}

#if defined(CFG_RISCV_ISA_V)
bool vfp_fault_is_vector(void)
{
	/*
	 * Units are handed over progressively, FP first, so once FP is on the
	 * only unit a disabled-unit trap can still be about is vector.
	 */
	return fp_is_enabled();
}
#endif

bool vfp_lazy_save_fp(struct vfp_state *state, bool force)
{
	if (state->fs == CSR_XSTATUS_FS_OFF && !force)
		return false;

	assert(!fp_is_enabled());
	fp_enable();
	state->fcsr = read_csr(CSR_FCSR);
	vfp_save_extension_regs(state->reg);
	fp_disable();

	return true;
}

#if defined(CFG_RISCV_ISA_V)
bool vfp_lazy_save_vec(struct vfp_state *state, bool force)
{
	if (!state->vregs || (state->vs == CSR_XSTATUS_VS_OFF && !force))
		return false;

	assert(!vec_is_enabled());
	vec_enable();
	riscv_vector_save(state->vregs);
	vec_disable();

	return true;
}
#endif

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	state->fs = read_fs();
	if (state->fs != CSR_XSTATUS_FS_OFF)
		fp_disable();
#if defined(CFG_RISCV_ISA_V)
	state->vs = read_vs();
	if (state->vs != CSR_XSTATUS_VS_OFF)
		vec_disable();
#endif
}

void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save)
{
	/* Each unit is saved only if its owner left it in use. */
	vfp_lazy_save_fp(state, force_save);
#if defined(CFG_RISCV_ISA_V)
	vfp_lazy_save_vec(state, force_save);
#endif
}

void vfp_lazy_restore_state(struct vfp_state *state, bool restore_fp,
			    bool restore_vec __maybe_unused)
{
	/*
	 * Restore exactly the units the caller says were saved. The flags are
	 * authoritative (not FS/VS), because the normal world is commonly
	 * entered with a unit lazily disabled (FS/VS == Off) while its
	 * registers are still live and were force-saved; those must be put back
	 * even though the saved FS/VS reads Off. xstatus.FS/VS are then set to
	 * what the owner had.
	 */
	if (restore_fp) {
		fp_enable();
		write_csr(CSR_FCSR, state->fcsr);
		vfp_restore_extension_regs(state->reg);
	}
#if defined(CFG_RISCV_ISA_V)
	if (restore_vec) {
		vec_enable();
		riscv_vector_restore(state->vregs);
	}
#endif
	write_fs(state->fs);
#if defined(CFG_RISCV_ISA_V)
	write_vs(state->vs);
#endif
}
