/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <assert.h>
#include <kernel/vfp.h>
#include "vfp_private.h"

#ifdef ARM32
bool vfp_is_enabled(void)
{
	return !!(vfp_read_fpexc() & FPEXC_EN);
}

void vfp_enable(void)
{
	vfp_write_fpexc(vfp_read_fpexc() | FPEXC_EN);
}

void vfp_disable(void)
{
	vfp_write_fpexc(vfp_read_fpexc() & ~FPEXC_EN);
}

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	uint32_t fpexc = vfp_read_fpexc();

	state->fpexc = fpexc;
	vfp_write_fpexc(fpexc & ~FPEXC_EN);
}

void vfp_lazy_save_state_final(struct vfp_state *state)
{
	if (state->fpexc & FPEXC_EN) {
		uint32_t fpexc = vfp_read_fpexc();

		assert(!(fpexc & FPEXC_EN));
		vfp_write_fpexc(fpexc | FPEXC_EN);
		state->fpscr = vfp_read_fpscr();
		vfp_save_extension_regs(state->reg);
		vfp_write_fpexc(fpexc);
	}
}

void vfp_lazy_restore_state(struct vfp_state *state, bool full_state)
{

	if (full_state) {
		/*
		 * Only restore VFP registers if they have been touched as they
		 * otherwise are intact.
		 */

		/* FPEXC is restored to what's in state->fpexc below */
		vfp_write_fpexc(vfp_read_fpexc() | FPEXC_EN);

		vfp_write_fpscr(state->fpscr);
		vfp_restore_extension_regs(state->reg);
	}
	vfp_write_fpexc(state->fpexc);
}
#endif /* ARM32 */

#ifdef ARM64
bool vfp_is_enabled(void)
{
	return (CPACR_EL1_FPEN(read_cpacr_el1()) & CPACR_EL1_FPEN_EL0EL1);
}

void vfp_enable(void)
{
	uint32_t val = read_cpacr_el1();

	val |= (CPACR_EL1_FPEN_EL0EL1 << CPACR_EL1_FPEN_SHIFT);
	write_cpacr_el1(val);
	isb();
}

void vfp_disable(void)
{
	uint32_t val = read_cpacr_el1();

	val &= ~(CPACR_EL1_FPEN_MASK << CPACR_EL1_FPEN_SHIFT);
	write_cpacr_el1(val);
	isb();
}

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	state->cpacr_el1 = read_cpacr_el1();
	vfp_disable();
}

void vfp_lazy_save_state_final(struct vfp_state *state)
{
	if ((CPACR_EL1_FPEN(state->cpacr_el1) & CPACR_EL1_FPEN_EL0EL1) ||
	    state->force_save) {
		assert(!vfp_is_enabled());
		vfp_enable();
		state->fpcr = read_fpcr();
		state->fpsr = read_fpsr();
		vfp_save_extension_regs(state->reg);
		vfp_disable();
	}
}

void vfp_lazy_restore_state(struct vfp_state *state, bool full_state)
{
	if (full_state) {
		/*
		 * Only restore VFP registers if they have been touched as they
		 * otherwise are intact.
		 */

		/* CPACR_EL1 is restored to what's in state->cpacr_el1 below */
		vfp_enable();
		write_fpcr(state->fpcr);
		write_fpsr(state->fpsr);
		vfp_restore_extension_regs(state->reg);
	}
	write_cpacr_el1(state->cpacr_el1);
	isb();
}
#endif /* ARM64 */
