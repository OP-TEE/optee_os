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
	unsigned long xstatus = read_csr(CSR_XSTATUS) & ~CSR_XSTATUS_FS_MASK;

	write_csr(CSR_XSTATUS, xstatus | SHIFT_U32(fs, CSR_XSTATUS_FS_SHIFT));
}

bool vfp_is_enabled(void)
{
	return read_fs() != CSR_XSTATUS_FS_OFF;
}

void vfp_enable(void)
{
	write_fs(CSR_XSTATUS_FS_CLEAN);
}

void vfp_disable(void)
{
	write_fs(CSR_XSTATUS_FS_OFF);
}

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	state->fs = read_fs();
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
}

void vfp_lazy_restore_state(struct vfp_state *state, bool full_state)
{
	if (full_state) {
		/*
		 * Only restore the FP registers if they have been touched as
		 * they otherwise are intact.
		 */

		/* FS is restored to what's in state->fs below */
		vfp_enable();
		write_csr(CSR_FCSR, state->fcsr);
		vfp_restore_extension_regs(state->reg);
	}
	write_fs(state->fs);
}
