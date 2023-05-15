/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef MUTEX_LOCKDEP_H
#define MUTEX_LOCKDEP_H

#include <compiler.h>
#include <kernel/mutex.h>

#ifdef CFG_LOCKDEP

void mutex_lock_check(struct mutex *m);

void mutex_trylock_check(struct mutex *m);

void mutex_unlock_check(struct mutex *m);

void mutex_destroy_check(struct mutex *m);

#else

static inline void mutex_lock_check(struct mutex *m __unused)
{}

static inline void mutex_trylock_check(struct mutex *m __unused)
{}

static inline void mutex_unlock_check(struct mutex *m __unused)
{}

static inline void mutex_destroy_check(struct mutex *m __unused)
{}

#endif /* !CFG_LOCKDEP */

#endif /* MUTEX_LOCKDEP_H */
