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

#ifndef KERNEL_VFP_H
#define KERNEL_VFP_H

#include <types_ext.h>
#include <compiler.h>

#ifdef ARM32
/*
 * Advanced SIMD/floating point state on ARMv7-A or ARMv8-A AArch32 has:
 * - 32 64-bit data registers
 * - FPSCR (32 bits)
 * - FPEXC (32 bits)
 */

#define VFP_NUM_REGS	32

struct vfp_reg {
	uint64_t v;
};

struct vfp_state {
	uint32_t fpexc;
	uint32_t fpscr;
	struct vfp_reg reg[VFP_NUM_REGS];
};
#endif

#ifdef ARM64
/*
 * Advanced SIMD/floating point state on ARMv8-A AArch64 has:
 * - 32 128-bit data registers
 * - FPSR (32 bits)
 * - FPCR (32 bits)
 * - CPACR_EL1.FPEN (2 bits)
 */

#define VFP_NUM_REGS	32

struct vfp_reg {
	uint8_t v[16];
} __aligned(16);

struct vfp_state {
	struct vfp_reg reg[VFP_NUM_REGS];
	uint32_t fpsr;
	uint32_t fpcr;
	uint32_t cpacr_el1;
	bool force_save; /* Save to reg even if VFP was not enabled */
};
#endif

#ifdef CFG_WITH_VFP
/* vfp_is_enabled() - Returns true if VFP is enabled */
bool vfp_is_enabled(void);

/* vfp_enable() - Enables vfp */
void vfp_enable(void);

/* vfp_disable() - Disables vfp */
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
 * vfp_lazy_save_state_init() - Saves VFP enable status and disables VFP
 * @state:	VFP state structure to initialize
 */
void vfp_lazy_save_state_init(struct vfp_state *state);

/*
 * vfp_lazy_save_state_final() - Saves rest of VFP state
 * @state:	VFP state to save to
 *
 * If VFP was enabled when vfp_lazy_save_state_init() was called: save rest
 * of state and disable VFP. Otherwise, do nothing.
 */
void vfp_lazy_save_state_final(struct vfp_state *state);

/*
 * vfp_lazy_restore_state() - Lazy restore VFP state
 * @state:		VFP state to restore
 *
 * Restores VFP enable status and also restores rest of VFP state if
 * vfp_lazy_save_state_final() was called on this state.
 */
void vfp_lazy_restore_state(struct vfp_state *state, bool full_state);

#endif /*KERNEL_VFP_H*/
