/* SPDX-License-Identifier: BSD-2-Clause */
/*-
 * Copyright (c) 2015-2019 Linaro Limited
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#ifndef __KERNEL_UNWIND
#define __KERNEL_UNWIND

#include <types_ext.h>

#if defined(CFG_UNWIND) && (TRACE_LEVEL > 0)
void print_kernel_stack(void);
#else
static inline void print_kernel_stack(void)
{
}
#endif

#ifdef CFG_UNWIND
/* Get current call stack as an array allocated on the heap */
vaddr_t *unw_get_kernel_stack(void);
#else
static inline void *unw_get_kernel_stack(void)
{
	return NULL;
}
#endif /* CFG_UNWIND  */

#endif /*__KERNEL_UNWIND*/
