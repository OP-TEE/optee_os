/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#include <asm.S>

	.fpu	neon

/* void vfp_save_extension_regs(uint64_t regs[VFP_NUM_REGS]); */
FUNC vfp_save_extension_regs , :
UNWIND(	.fnstart)
	vstm	r0!, {d0-d15}
	vstm	r0, {d16-d31}
	bx	lr
UNWIND(	.fnend)
END_FUNC vfp_save_extension_regs

/* void vfp_restore_extension_regs(uint64_t regs[VFP_NUM_REGS]); */
FUNC vfp_restore_extension_regs , :
UNWIND(	.fnstart)
	vldm	r0!, {d0-d15}
	vldm	r0, {d16-d31}
	bx	lr
UNWIND(	.fnend)
END_FUNC vfp_restore_extension_regs

/* void vfp_write_fpexc(uint32_t fpexc) */
FUNC vfp_write_fpexc , :
UNWIND(	.fnstart)
	vmsr	fpexc, r0
	bx	lr
UNWIND(	.fnend)
END_FUNC vfp_write_fpexc

/* uint32_t vfp_read_fpexc(void) */
FUNC vfp_read_fpexc , :
UNWIND(	.fnstart)
	vmrs	r0, fpexc
	bx	lr
UNWIND(	.fnend)
END_FUNC vfp_read_fpexc

/* void vfp_write_fpscr(uint32_t fpscr) */
FUNC vfp_write_fpscr , :
UNWIND(	.fnstart)
	vmsr	fpscr, r0
	bx	lr
UNWIND(	.fnend)
END_FUNC vfp_write_fpscr

/* uint32_t vfp_read_fpscr(void) */
FUNC vfp_read_fpscr , :
UNWIND(	.fnstart)
	vmrs	r0, fpscr
	bx	lr
UNWIND(	.fnend)
END_FUNC vfp_read_fpscr
