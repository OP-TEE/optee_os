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

#if defined(CFG_RISCV_VEC)
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
#endif

bool vfp_is_enabled(void)
{
	if (read_fs() != CSR_XSTATUS_FS_OFF)
		return true;
#if defined(CFG_RISCV_VEC)
	if (read_vs() != CSR_XSTATUS_VS_OFF)
		return true;
#endif
	return false;
}

void vfp_enable(void)
{
	set_csr(CSR_XSTATUS, CSR_XSTATUS_FS_MASK);
#if defined(CFG_RISCV_VEC)
	set_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
#endif
}

void vfp_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_FS_MASK);
#if defined(CFG_RISCV_VEC)
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
#endif
}

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	state->fs = read_fs();
#if defined(CFG_RISCV_VEC)
	state->vs = read_vs();
#endif
	vfp_disable();
}

void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save)
{
	if (state->fs != CSR_XSTATUS_FS_OFF || force_save) {
		assert(!vfp_is_enabled());
		vfp_enable();
		state->fcsr = read_csr(CSR_FCSR);
		vfp_save_extension_regs(state->reg);
		vfp_disable();
	}
#if defined(CFG_RISCV_VEC)
	if ((state->vs != CSR_XSTATUS_VS_OFF || force_save) && state->vregs) {
		assert(!vfp_is_enabled());
		vfp_enable();
		riscv_vector_save(state->vregs);
		vfp_disable();
	}
#endif
}

void vfp_lazy_restore_state(struct vfp_state *state, bool full_state)
{
	if (full_state) {
		/*
		 * Only restore the registers if they have been touched as
		 * they otherwise are intact.
		 */

		/* FS and VS are restored to what's in state below */
		vfp_enable();
		write_csr(CSR_FCSR, state->fcsr);
		vfp_restore_extension_regs(state->reg);
#if defined(CFG_RISCV_VEC)
		if (state->vregs)
			riscv_vector_restore(state->vregs);
#endif
	}
	write_fs(state->fs);
#if defined(CFG_RISCV_VEC)
	write_vs(state->vs);
#endif
}
