/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2023, Amazon.com Inc. or its affiliates. All rights Reserved.
 */

#ifndef __KERNEL_USER_ACCESS_ARCH_H
#define __KERNEL_USER_ACCESS_ARCH_H

#include <riscv.h>

#ifdef CFG_PAN
/* Enter a section where user mode access is temporarily enabled. */
static inline void enter_user_access(void)
{
	set_csr(CSR_XSTATUS, CSR_XSTATUS_SUM);
}

/* Exit from the section where user mode access was temporarily enabled. */
static inline void exit_user_access(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_SUM);
}
#else
static inline void enter_user_access(void) {}
static inline void exit_user_access(void) {}
#endif /* CFG_PAN */

#endif /* __KERNEL_USER_ACCESS_ARCH_H */
