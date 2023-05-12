/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Amazon.com Inc. or its affiliates. All rights Reserved.
 */

#ifndef __KERNEL_USER_ACCESS_ARCH_H
#define __KERNEL_USER_ACCESS_ARCH_H

#include <arm.h>

#ifdef CFG_PAN
/* Enter a section where user mode access is temporarily enabled. */
static inline void enter_user_access(void)
{
	write_pan_disable();
}

/* Exit from the section where user mode access was temporarily enabled. */
static inline void exit_user_access(void)
{
	write_pan_enable();
}
#else
static inline void enter_user_access(void) {}
static inline void exit_user_access(void) {}
#endif /* CFG_PAN */

#endif /* __KERNEL_USER_ACCESS_ARCH_H */
