/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RiscStar
 */

#ifndef __KERNEL_STACK_CHECK_H
#define __KERNEL_STACK_CHECK_H

extern void *__stack_chk_guard;

typedef void (*stack_chk_fail_cb_t)(void);

/* Test hook, called from __stack_chk_fail() before panicking */
void stack_chk_set_fail_cb(stack_chk_fail_cb_t cb);

#endif /*__KERNEL_STACK_CHECK_H*/
