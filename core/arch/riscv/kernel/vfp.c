// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <assert.h>
#include <kernel/vfp.h>
#include <riscv.h>
#include "vfp_private.h"

#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
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

bool vfp_is_enabled(void)
{
	return read_vs() != CSR_XSTATUS_VS_OFF;
}

void vfp_enable(void)
{
	set_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
}

void vfp_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
}

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	state->vs = read_vs();
	vfp_disable();
}

void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save)
{
	if (state->vs != CSR_XSTATUS_VS_OFF || force_save) {
		assert(!vfp_is_enabled() && state->vregs);
		vfp_enable();
		riscv_vector_save(state->vregs);
		vfp_disable();
	}
}

void vfp_lazy_restore_state(struct vfp_state *state, bool full_state)
{
	if (full_state) {
		/*
		 * Only restore the registers if they have been touched, as
		 * they otherwise are intact.
		 */

		/* VS is restored to what's in state->vs below */
		assert(state->vregs);
		vfp_enable();
		riscv_vector_restore(state->vregs);
	}
	write_vs(state->vs);
}
#else
void vfp_lazy_save_state_init(struct vfp_state *state __unused)
{
}

void vfp_lazy_save_state_final(struct vfp_state *state __unused,
			       bool force_save __unused)
{
}

void vfp_lazy_restore_state(struct vfp_state *state __unused,
			    bool full_state __unused)
{
}
#endif /* CFG_WITH_VFP && CFG_RISCV_VEC */
