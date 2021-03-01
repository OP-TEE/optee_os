/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2017, Linaro Limited
 */
#ifndef KERNEL_MUTEX_H
#define KERNEL_MUTEX_H

#include <kernel/refcount.h>
#include <kernel/wait_queue.h>
#include <sys/queue.h>
#include <types_ext.h>

struct mutex {
	unsigned spin_lock;	/* used when operating on this struct */
	struct wait_queue wq;
	short state;		/* -1: write, 0: unlocked, > 0: readers */
};

#define MUTEX_INITIALIZER { .wq = WAIT_QUEUE_INITIALIZER }

struct recursive_mutex {
	struct mutex m;		/* used when lock_depth goes 0 -> 1 or 1 -> 0 */
	short int owner;
	struct refcount lock_depth;
};

#define RECURSIVE_MUTEX_INITIALIZER { .m = MUTEX_INITIALIZER, \
				      .owner = THREAD_ID_INVALID }

TAILQ_HEAD(mutex_head, mutex);

void mutex_init(struct mutex *m);
void mutex_destroy(struct mutex *m);

void mutex_init_recursive(struct recursive_mutex *m);
void mutex_destroy_recursive(struct recursive_mutex *m);
unsigned int mutex_get_recursive_lock_depth(struct recursive_mutex *m);

#ifdef CFG_MUTEX_DEBUG
void mutex_unlock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_unlock(m) mutex_unlock_debug((m), __FILE__, __LINE__)

void mutex_lock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_lock(m) mutex_lock_debug((m), __FILE__, __LINE__)

bool mutex_trylock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_trylock(m) mutex_trylock_debug((m), __FILE__, __LINE__)

void mutex_read_unlock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_read_unlock(m) mutex_read_unlock_debug((m), __FILE__, __LINE__)

void mutex_read_lock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_read_lock(m) mutex_read_lock_debug((m), __FILE__, __LINE__)

bool mutex_read_trylock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_read_trylock(m) mutex_read_trylock_debug((m), __FILE__, __LINE__)

void mutex_unlock_recursive_debug(struct recursive_mutex *m, const char *fname,
				  int lineno);
#define mutex_unlock_recursive(m) mutex_unlock_recursive_debug((m), __FILE__, \
							       __LINE__)

void mutex_lock_recursive_debug(struct recursive_mutex *m, const char *fname,
				int lineno);
#define mutex_lock_recursive(m) mutex_lock_recursive_debug((m), __FILE__, \
							   __LINE__)
#else
void mutex_unlock(struct mutex *m);
void mutex_lock(struct mutex *m);
bool mutex_trylock(struct mutex *m);
void mutex_read_unlock(struct mutex *m);
void mutex_read_lock(struct mutex *m);
bool mutex_read_trylock(struct mutex *m);

void mutex_unlock_recursive(struct recursive_mutex *m);
void mutex_lock_recursive(struct recursive_mutex *m);
#endif

struct condvar {
	unsigned spin_lock;
	struct mutex *m;
};
#define CONDVAR_INITIALIZER { .m = NULL }

void condvar_init(struct condvar *cv);
void condvar_destroy(struct condvar *cv);

#ifdef CFG_MUTEX_DEBUG
void condvar_signal_debug(struct condvar *cv, const char *fname, int lineno);
#define condvar_signal(cv) condvar_signal_debug((cv), __FILE__, __LINE__)

void condvar_broadcast_debug(struct condvar *cv, const char *fname, int lineno);
#define condvar_broadcast(cv) condvar_broadcast_debug((cv), __FILE__, __LINE__)

void condvar_wait_debug(struct condvar *cv, struct mutex *m,
			const char *fname, int lineno);
#define condvar_wait(cv, m) condvar_wait_debug((cv), (m), __FILE__, __LINE__)
#else
void condvar_signal(struct condvar *cv);
void condvar_broadcast(struct condvar *cv);
void condvar_wait(struct condvar *cv, struct mutex *m);
#endif

#endif /*KERNEL_MUTEX_H*/

