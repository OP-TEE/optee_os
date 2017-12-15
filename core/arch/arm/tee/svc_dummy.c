// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <kernel/thread.h>
#include <kernel/panic.h>
#include <tee/arch_svc.h>

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 *
 * Not strictly needed in this case, but we need to be compatible with the
 * one in core/arch/arm/tee/arch_svc.c
 */
void __weak __noreturn tee_svc_handler(struct thread_svc_regs *regs __unused)
{
	/* "Can't happen" as we have no user space TAs */
	panic();
}
