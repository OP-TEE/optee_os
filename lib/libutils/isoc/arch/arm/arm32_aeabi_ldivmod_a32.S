/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <asm.S>

/*
 * This assembly source is used both in kernel and userland
 * hence define unwind resources that match both environments.
 */
#if defined(CFG_UNWIND)
#define LOCAL_UNWIND(...)	__VA_ARGS__
#else
#define LOCAL_UNWIND(...)
#endif

/*
 * __value_in_regs lldiv_t __aeabi_ldivmod( long long n, long long d)
 */
FUNC __aeabi_ldivmod , :
LOCAL_UNWIND(.fnstart)
	push	{ip, lr}
LOCAL_UNWIND(.save {ip, lr})
	push	{r0-r3}
LOCAL_UNWIND(.save {r0-r3})
	mov	r0, sp
	bl	__l_divmod
	pop	{r0-r3}
	pop	{ip, pc}
LOCAL_UNWIND(.fnend)
END_FUNC __aeabi_ldivmod

/*
 * __value_in_regs ulldiv_t __aeabi_uldivmod(
 *		unsigned long long n, unsigned long long d)
 */
FUNC __aeabi_uldivmod , :
LOCAL_UNWIND(.fnstart)
	push	{ip, lr}
LOCAL_UNWIND(.save {ip, lr})
	push	{r0-r3}
LOCAL_UNWIND(.save {r0-r3})
	mov	r0, sp
	bl	__ul_divmod
	pop	{r0-r3}
	pop	{ip, pc}
LOCAL_UNWIND(.fnend)
END_FUNC __aeabi_uldivmod
