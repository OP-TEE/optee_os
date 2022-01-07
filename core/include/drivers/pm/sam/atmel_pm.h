/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */
#ifndef __DRIVERS_PM_SAM_ATMEL_PM_H
#define __DRIVERS_PM_SAM_ATMEL_PM_H

#include <compiler.h>
#include <stdbool.h>
#include <tee_api_types.h>
#include <types_ext.h>

struct sm_nsec_ctx;

#if defined(CFG_ATMEL_PM)

static inline bool atmel_pm_suspend_available(void)
{
	return true;
}

void atmel_pm_cpu_idle(void);

TEE_Result atmel_pm_suspend(uintptr_t entry, struct sm_nsec_ctx *nsec);

TEE_Result sama5d2_pm_init(const void *fdt, vaddr_t shdwc);

#else

static inline void atmel_pm_cpu_idle(void) {};

static inline bool atmel_pm_suspend_available(void)
{
	return false;
}

static inline TEE_Result atmel_pm_suspend(uintptr_t entry __unused,
					  struct sm_nsec_ctx *nsec __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result sama5d2_pm_init(const void *fdt __unused,
					 vaddr_t shdwc __unused)
{
	return TEE_SUCCESS;
}

#endif

#endif /* __DRIVERS_PM_SAM_ATMEL_PM_H */
