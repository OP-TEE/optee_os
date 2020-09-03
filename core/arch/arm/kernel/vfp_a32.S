/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#include <asm.S>

	.fpu	neon

/* void vfp_save_extension_regs(uint64_t regs[VFP_NUM_REGS]); */
FUNC vfp_save_extension_regs , :
	vstm	r0!, {d0-d15}
	vstm	r0, {d16-d31}
	bx	lr
END_FUNC vfp_save_extension_regs

/* void vfp_restore_extension_regs(uint64_t regs[VFP_NUM_REGS]); */
FUNC vfp_restore_extension_regs , :
	vldm	r0!, {d0-d15}
	vldm	r0, {d16-d31}
	bx	lr
END_FUNC vfp_restore_extension_regs

/* void vfp_write_fpexc(uint32_t fpexc) */
FUNC vfp_write_fpexc , :
	vmsr	fpexc, r0
	bx	lr
END_FUNC vfp_write_fpexc

/* uint32_t vfp_read_fpexc(void) */
FUNC vfp_read_fpexc , :
	vmrs	r0, fpexc
	bx	lr
END_FUNC vfp_read_fpexc

/* void vfp_write_fpscr(uint32_t fpscr) */
FUNC vfp_write_fpscr , :
	vmsr	fpscr, r0
	bx	lr
END_FUNC vfp_write_fpscr

/* uint32_t vfp_read_fpscr(void) */
FUNC vfp_read_fpscr , :
	vmrs	r0, fpscr
	bx	lr
END_FUNC vfp_read_fpscr
