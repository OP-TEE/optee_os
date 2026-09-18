/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv.h>
#include <riscv_macros.S>

/*
 * The FP unit must be enabled by the caller: fcsr is not touched here, it
 * is handled in C by vfp.c.
 */

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

/* void vfp_clear_extension_regs(void); */
FUNC vfp_clear_extension_regs , :
	.irp n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, \
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
#if __riscv_flen == 32
	fmv.w.x	f\n, zero
#else
	fmv.d.x	f\n, zero
#endif
	.endr
	ret
END_FUNC vfp_clear_extension_regs
