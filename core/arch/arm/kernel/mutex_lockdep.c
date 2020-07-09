// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <assert.h>
#include <kernel/lockdep.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <sys/queue.h>
#include <trace.h>

#include "mutex_lockdep.h"

/* Global graph of all mutexes used in the code */
static struct lockdep_node_head graph = TAILQ_HEAD_INITIALIZER(graph);

/* Protects @graph */
static unsigned int graph_lock = SPINLOCK_UNLOCK;

/*
 * One queue per thread, contains the mutexes the thread owns at any point in
 * time (in aquire order)
 */
static struct lockdep_lock_head owned[CFG_NUM_THREADS];

void mutex_lockdep_init(void)
{
	int n = 0;

	for (n = 0; n < CFG_NUM_THREADS; n++)
		TAILQ_INIT(&owned[n]);

	DMSG("lockdep is enabled for mutexes");
}

void mutex_lock_check(struct mutex *m)
{
	short int thread = thread_get_id();
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&graph_lock);
	lockdep_lock_acquire(&graph, &owned[thread], (uintptr_t)m);
	cpu_spin_unlock_xrestore(&graph_lock, exceptions);
}

void mutex_trylock_check(struct mutex *m)
{
	short int thread = thread_get_id();
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&graph_lock);
	lockdep_lock_tryacquire(&graph, &owned[thread], (uintptr_t)m);
	cpu_spin_unlock_xrestore(&graph_lock, exceptions);
}

void mutex_unlock_check(struct mutex *m)
{
	short int thread = thread_get_id();
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&graph_lock);
	lockdep_lock_release(&owned[thread], (uintptr_t)m);
	cpu_spin_unlock_xrestore(&graph_lock, exceptions);
}

void mutex_destroy_check(struct mutex *m)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&graph_lock);

	lockdep_lock_destroy(&graph, (uintptr_t)m);
	cpu_spin_unlock_xrestore(&graph_lock, exceptions);
}
