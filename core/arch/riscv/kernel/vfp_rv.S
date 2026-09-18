/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv.h>
#include <riscv_macros.S>

/* void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_save_extension_regs , :
	store_fregs a0, 0, 0, 31
	ret
END_FUNC vfp_save_extension_regs

/* void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_restore_extension_regs , :
	load_fregs a0, 0, 0, 31
	ret
END_FUNC vfp_restore_extension_regs

/*
 * void vfp_clear_extension_regs(void);
 *
 * Reset the FP context to a clean state: zero f0..f31 and fcsr. The FP
 * unit must be enabled by the caller.
 */
FUNC vfp_clear_extension_regs , :
	clear_fregs 0, 31
	csrw	fcsr, zero
	ret
END_FUNC vfp_clear_extension_regs
