/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __KERNEL_USER_MODE_CTX_STRUCT_H
#define __KERNEL_USER_MODE_CTX_STRUCT_H

#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/tee_mmu_types.h>

struct user_mode_ctx {
	struct vm_info vm_info;
	struct tee_pager_area_head *areas;
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct tee_ta_ctx ctx;
};
#endif /*__KERNEL_USER_MODE_CTX_STRUCT_H*/

