/*
 * Copyright (c) 2015-2016, Linaro Limited
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

#include <asm.S>
#include <kernel/unwind.h>

	.section .text.vfp_asm

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
