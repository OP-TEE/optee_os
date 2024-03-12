/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics
 */
#ifndef __KERNEL_MUTEX_PM_AWARE_H
#define __KERNEL_MUTEX_PM_AWARE_H

#include <kernel/mutex.h>
#include <kernel/spinlock.h>

/*
 * struct mutex_pm_aware - Mutex usable in PM atomic sequence
 *
 * Some resources need a mutex protection for runtime operations but are
 * also accessed during specific system power transition (PM power off,
 * suspend and resume) that operate in atomic execution environment where
 * non-secure world is not operational, for example in fastcall SMC entries
 * of the PSCI services. In such case we cannot take a mutex and we expect
 * the mutex is unlocked. Additionally a spinning lock is attempted to be
 * locked to check the resource access consistency.
 *
 * Core intentionally panics in case of unexpected resource access contention:
 * - When a thread requests a mutex held by a non-thread context;
 * - When a non-thread context requests a mutex held by a thread;
 * - When a non-thread context requests a mutex held by a non-thread context.
 */
struct mutex_pm_aware {
	struct mutex mutex;	/* access protection in thread context */
	unsigned int lock;	/* access consistency in PM context */
};

#define MUTEX_PM_AWARE_INITIALIZER { \
		.mutex = MUTEX_INITIALIZER, \
		.lock = SPINLOCK_UNLOCK, \
	}

void mutex_pm_aware_init(struct mutex_pm_aware *m);
void mutex_pm_aware_destroy(struct mutex_pm_aware *m);
void mutex_pm_aware_lock(struct mutex_pm_aware *m);
void mutex_pm_aware_unlock(struct mutex_pm_aware *m);

#endif /*__KERNEL_MUTEX_PM_AWARE_H*/

