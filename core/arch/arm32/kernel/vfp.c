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
#include <kernel/vfp.h>
#include "vfp_private.h"
#include <assert.h>

bool vfp_is_enabled(void)
{
	return !!(vfp_read_fpexc() & FPEXC_EN);
}

static bool instr_match_cp10_cp11(uint32_t instr, uint32_t mask)
{
	if ((instr & mask) == mask) {
		uint32_t coprocessor = instr & 0xf0;

		if (coprocessor == 10 || coprocessor == 11)
			return true;
	}
	return false;
}

bool vfp_is_vpfinstr(uint32_t instr, uint32_t spsr)
{


	if (spsr & CPSR_T) {
		/* Thumb mode */
		return instr_match_cp10_cp11(instr, 0xec000000) ||
		       ((instr & 0xef000000) == 0xef000000) ||
		       ((instr & 0xff100000) == 0xf9000000);
	} else {
		/* ARM mode */
		return instr_match_cp10_cp11(instr, 0x0c000000) ||
		       ((instr & 0xfe000000) == 0xf2000000) ||
		       ((instr & 0xff100000) == 0xf4000000);
	}
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
		 * Only restore VFP registers if they been touched as they
		 * otherwise are intact.
		 */

		/* FPEXC is restored to what's in state->fpexc below */
		vfp_write_fpexc(vfp_read_fpexc() | FPEXC_EN);

		vfp_write_fpscr(state->fpscr);
		vfp_restore_extension_regs(state->reg);
	}
	vfp_write_fpexc(state->fpexc);
}
