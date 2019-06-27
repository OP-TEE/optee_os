/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __KERNEL_LOCKDEP_H
#define __KERNEL_LOCKDEP_H

#include <compiler.h>
#include <kernel/panic.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

/*
 * Lock graph. If node A has an edge to node B, then A was locked before B in
 * the same thread of execution.
 */

struct lockdep_edge {
	struct lockdep_node *to;
	uintptr_t thread_id;
	vaddr_t *call_stack_from;
	vaddr_t *call_stack_to;
	STAILQ_ENTRY(lockdep_edge) link;
};

STAILQ_HEAD(lockdep_edge_head, lockdep_edge);

struct lockdep_node {
	uintptr_t lock_id; /* For instance, address of actual lock object */
	struct lockdep_edge_head edges;
	TAILQ_ENTRY(lockdep_node) link;
	uint8_t flags; /* Used temporarily when walking the graph */
};

TAILQ_HEAD(lockdep_node_head, lockdep_node);

/* Per-thread queue of currently owned locks (point to nodes in the graph) */

struct lockdep_lock {
	struct lockdep_node *node;
	vaddr_t *call_stack;
	TAILQ_ENTRY(lockdep_lock) link;
};

TAILQ_HEAD(lockdep_lock_head, lockdep_lock);

#ifdef CFG_LOCKDEP

/*
 * Functions used internally and for testing the algorithm. Actual locking code
 * should use the wrappers below (which panic in case of error).
 */
TEE_Result __lockdep_lock_acquire(struct lockdep_node_head *graph,
				  struct lockdep_lock_head *owned,
				  uintptr_t id);
TEE_Result __lockdep_lock_tryacquire(struct lockdep_node_head *graph,
				     struct lockdep_lock_head *owned,
				     uintptr_t id);
TEE_Result __lockdep_lock_release(struct lockdep_lock_head *owned,
				  uintptr_t id);

/* Delete all elements in @graph */
void lockdep_graph_delete(struct lockdep_node_head *graph);

/* Delete all elements in @queue */
void lockdep_queue_delete(struct lockdep_lock_head *queue);

/*
 * Acquire lock @id, while already holding the locks in @owned.
 * @owned represent the caller; there should be one instance per thread of
 * execution. @graph is the directed acyclic graph (DAG) to be used for
 * potential deadlock detection; use the same @graph for all the locks of the
 * same type as lock @id.
 *
 * This function will panic() if the acquire operation would result in a lock
 * hierarchy violation (potential deadlock).
 */
static inline void lockdep_lock_acquire(struct lockdep_node_head *graph,
					struct lockdep_lock_head *owned,
					uintptr_t id)
{
	TEE_Result res = __lockdep_lock_acquire(graph, owned, id);

	if (res) {
		EMSG("lockdep: error %#" PRIx32, res);
		panic();
	}
}

/*
 * Non-blocking acquire lock @id, while already holding the locks in @owned.
 * @owned represent the caller; there should be one instance per thread of
 * execution. @graph is the directed acyclic graph (DAG) to be used for
 * potential deadlock detection; use the same @graph for all the locks of the
 * same type as lock @id.
 */
static inline void lockdep_lock_tryacquire(struct lockdep_node_head *graph,
					   struct lockdep_lock_head *owned,
					   uintptr_t id)
{
	TEE_Result res = __lockdep_lock_tryacquire(graph, owned, id);

	if (res) {
		EMSG("lockdep: error %#" PRIx32, res);
		panic();
	}
}

/*
 * Release lock @id. The lock is removed from @owned.
 *
 * This function will panic() if the lock is not held by the caller.
 */
static inline void lockdep_lock_release(struct lockdep_lock_head *owned,
					uintptr_t id)
{
	TEE_Result res = __lockdep_lock_release(owned, id);

	if (res) {
		EMSG("lockdep: error %#" PRIx32, res);
		panic();
	}
}

/*
 * Destroy lock @id in @graph. The lock is freed.
 */
void lockdep_lock_destroy(struct lockdep_node_head *graph, uintptr_t id);

/* Initialize lockdep for mutex objects (kernel/mutex.h) */
void mutex_lockdep_init(void);

#else /* CFG_LOCKDEP */

static inline void lockdep_lock_acquire(struct lockdep_node_head *g __unused,
					struct lockdep_lock_head *o __unused,
					uintptr_t id __unused)
{}

static inline void lockdep_lock_release(struct lockdep_lock_head *o __unused,
					uintptr_t id __unused)
{}

static inline void
lockdep_lock_destroy(struct lockdep_node_head *graph __unused,
		     uintptr_t id __unused)
{}

static inline void mutex_lockdep_init(void)
{}

#endif /* !CFG_LOCKDEP */

#endif /* !__KERNEL_LOCKDEP_H */
