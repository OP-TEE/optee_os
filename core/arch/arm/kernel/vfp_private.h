/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef VFP_PRIVATE
#define VFP_PRIVATE

#include <kernel/vfp.h>

void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]);
void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]);
void vfp_clear_extension_regs(void);

#ifdef ARM32

#define FPEXC_EN	(1 << 30)

/*
 * These functions can't be implemented in inline assembly when compiling
 * for thumb mode, to make it easy always implement then in ARM assembly as
 * ordinary functions.
 */
void vfp_write_fpexc(uint32_t fpexc);
uint32_t vfp_read_fpexc(void);
void vfp_write_fpscr(uint32_t fpscr);
uint32_t vfp_read_fpscr(void);

#endif /* ARM32 */

#endif /*VFP_PRIVATE*/
