// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <assert.h>
#include <config.h>
#include <kernel/lockdep.h>
#include <kernel/unwind.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <util.h>

/* lockdep_node::flags values */
/* Flags used for depth-first topological sorting */
#define LOCKDEP_NODE_TEMP_MARK		BIT(0)
#define LOCKDEP_NODE_PERM_MARK		BIT(1)
/* Flag used during breadth-first search (print shortest cycle) */
#define LOCKDEP_NODE_BFS_VISITED	BIT(2)

/* Find node in graph or add it */
static struct lockdep_node *lockdep_add_to_graph(
				struct lockdep_node_head *graph,
				uintptr_t lock_id)
{
	struct lockdep_node *node = NULL;

	assert(graph);
	TAILQ_FOREACH(node, graph, link)
		if (node->lock_id == lock_id)
			return node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->lock_id = lock_id;
	STAILQ_INIT(&node->edges);
	TAILQ_INSERT_TAIL(graph, node, link);

	return node;
}

static vaddr_t *dup_call_stack(vaddr_t *stack)
{
	vaddr_t *nstack = NULL;
	int n = 0;

	if (!stack)
		return NULL;

	while (stack[n])
		n++;

	nstack = malloc((n + 1) * sizeof(vaddr_t));
	if (!nstack)
		return NULL;

	memcpy(nstack, stack, (n + 1) * sizeof(vaddr_t));

	return nstack;
}

static void lockdep_print_call_stack(vaddr_t *stack)
{
	vaddr_t *p = NULL;

	if (!IS_ENABLED(CFG_LOCKDEP_RECORD_STACK))
		return;

	EMSG_RAW("Call stack:");
	for (p = stack; p && *p; p++)
		EMSG_RAW(" %#" PRIxPTR, *p);
}

static TEE_Result lockdep_add_edge(struct lockdep_node *from,
				   struct lockdep_node *to,
				   vaddr_t *call_stack_from,
				   vaddr_t *call_stack_to,
				   uintptr_t thread_id)
{
	struct lockdep_edge *edge = NULL;

	STAILQ_FOREACH(edge, &from->edges, link)
		if (edge->to == to)
			return TEE_SUCCESS;

	edge = calloc(1, sizeof(*edge));
	if (!edge)
		return TEE_ERROR_OUT_OF_MEMORY;
	edge->to = to;
	edge->call_stack_from = dup_call_stack(call_stack_from);
	edge->call_stack_to = dup_call_stack(call_stack_to);
	edge->thread_id = thread_id;
	STAILQ_INSERT_TAIL(&from->edges, edge, link);

	return TEE_SUCCESS;
}

struct lockdep_bfs {
	struct lockdep_node *node;
	uintptr_t *path;
	int pathlen;
	TAILQ_ENTRY(lockdep_bfs) link;
};

TAILQ_HEAD(lockdep_bfs_head, lockdep_bfs);

static void lockdep_bfs_queue_delete(struct lockdep_bfs_head *queue)
{
	struct lockdep_bfs *cur = NULL;
	struct lockdep_bfs *next = NULL;

	TAILQ_FOREACH_SAFE(cur, queue, link, next) {
		TAILQ_REMOVE(queue, cur, link);
		free(cur->path);
		free(cur);
	}
}

/*
 * Print shortest cycle in @graph that contains @node.
 * This function performs an iterative breadth-first search starting from @node,
 * and stops when it reaches @node again. In each node we're tracking the path
 * from the start node.
 */
static uintptr_t *lockdep_graph_get_shortest_cycle(struct lockdep_node *node)
{
	struct lockdep_bfs_head queue;
	struct lockdep_bfs *qe = NULL;
	uintptr_t *ret = NULL;

	TAILQ_INIT(&queue);
	node->flags |= LOCKDEP_NODE_BFS_VISITED;

	qe = calloc(1, sizeof(*qe));
	if (!qe)
		goto out;
	qe->node = node;
	qe->path = malloc(sizeof(uintptr_t));
	if (!qe->path)
		goto out;
	qe->path[0] = node->lock_id;
	qe->pathlen = 1;
	TAILQ_INSERT_TAIL(&queue, qe, link);

	while (!TAILQ_EMPTY(&queue)) {
		struct lockdep_node *n = NULL;
		struct lockdep_edge *e = NULL;

		qe = TAILQ_FIRST(&queue);
		n = qe->node;
		TAILQ_REMOVE(&queue, qe, link);

		STAILQ_FOREACH(e, &n->edges, link) {
			if (e->to->lock_id == node->lock_id) {
				uintptr_t *tmp = NULL;
				size_t nlen = qe->pathlen + 1;

				/*
				 * Cycle found. Terminate cycle path with NULL
				 * and return it.
				 */
				tmp = realloc(qe->path,
					      nlen * sizeof(uintptr_t));
				if (!tmp) {
					EMSG("Out of memory");
					free(qe->path);
					ret = NULL;
					goto out;
				}
				qe->path = tmp;
				qe->path[nlen - 1] = 0;
				ret = qe->path;
				goto out;
			}

			if (!(e->to->flags & LOCKDEP_NODE_BFS_VISITED)) {
				size_t nlen = 0;
				struct lockdep_bfs *nqe = NULL;

				e->to->flags |= LOCKDEP_NODE_BFS_VISITED;

				nlen = qe->pathlen + 1;
				nqe = calloc(1, sizeof(*nqe));
				if (!nqe)
					goto out;
				nqe->node = e->to;
				nqe->path = malloc(nlen * sizeof(uintptr_t));
				if (!nqe->path)
					goto out;
				nqe->pathlen = nlen;
				memcpy(nqe->path, qe->path,
				       qe->pathlen * sizeof(uintptr_t));
				nqe->path[nlen - 1] = e->to->lock_id;
				TAILQ_INSERT_TAIL(&queue, nqe, link);
			}
		}
		free(qe->path);
		free(qe);
		qe = NULL;
	}

out:
	free(qe);
	lockdep_bfs_queue_delete(&queue);
	return ret;
}

static TEE_Result lockdep_visit(struct lockdep_node *node)
{
	struct lockdep_edge *e = NULL;

	if (node->flags & LOCKDEP_NODE_PERM_MARK)
		return TEE_SUCCESS;

	if (node->flags & LOCKDEP_NODE_TEMP_MARK)
		return TEE_ERROR_BAD_STATE;	/* Not a DAG! */

	node->flags |= LOCKDEP_NODE_TEMP_MARK;

	STAILQ_FOREACH(e, &node->edges, link) {
		TEE_Result res = lockdep_visit(e->to);

		if (res)
			return res;
	}

	node->flags |= LOCKDEP_NODE_PERM_MARK;
	return TEE_SUCCESS;
}

static TEE_Result lockdep_graph_sort(struct lockdep_node_head *graph)
{
	struct lockdep_node *node = NULL;

	TAILQ_FOREACH(node, graph, link) {
		if (!node->flags) {
			/* Unmarked node */
			TEE_Result res = lockdep_visit(node);

			if (res)
				return res;
		}
	}

	TAILQ_FOREACH(node, graph, link)
		node->flags = 0;

	return TEE_SUCCESS;
}

static struct lockdep_edge *lockdep_find_edge(struct lockdep_node_head *graph,
					      uintptr_t from, uintptr_t to)
{
	struct lockdep_node *node = NULL;
	struct lockdep_edge *edge = NULL;

	TAILQ_FOREACH(node, graph, link)
		if (node->lock_id == from)
			STAILQ_FOREACH(edge, &node->edges, link)
				if (edge->to->lock_id == to)
					return edge;
	return NULL;
}

static void lockdep_print_edge_info(uintptr_t from __maybe_unused,
				    struct lockdep_edge *edge)
{
	uintptr_t __maybe_unused to = edge->to->lock_id;
	const char __maybe_unused *at_msg = "";
	const char __maybe_unused *acq_msg = "";

	if (IS_ENABLED(CFG_LOCKDEP_RECORD_STACK)) {
		at_msg = " at:";
		acq_msg = " acquired at:";
	}

	EMSG_RAW("-> Thread %#" PRIxPTR " acquired lock %#" PRIxPTR "%s",
		 edge->thread_id, to, at_msg);
	lockdep_print_call_stack(edge->call_stack_to);
	EMSG_RAW("...while holding lock %#" PRIxPTR "%s",
		 from, acq_msg);
	lockdep_print_call_stack(edge->call_stack_from);
}

/*
 * Find cycle containing @node in the lock graph, then print full debug
 * information about each edge (thread that acquired the locks and call stacks)
 */
static void lockdep_print_cycle_info(struct lockdep_node_head *graph,
				     struct lockdep_node *node)
{
	struct lockdep_edge *edge = NULL;
	uintptr_t *cycle = NULL;
	uintptr_t *p = NULL;
	uintptr_t from = 0;
	uintptr_t to = 0;

	cycle = lockdep_graph_get_shortest_cycle(node);
	assert(cycle && cycle[0]);
	EMSG_RAW("-> Shortest cycle:");
	for (p = cycle; *p; p++)
		EMSG_RAW(" Lock %#" PRIxPTR, *p);
	for (p = cycle; ; p++) {
		if (!*p) {
			assert(p != cycle);
			from = to;
			to = cycle[0];
			edge = lockdep_find_edge(graph, from, to);
			lockdep_print_edge_info(from, edge);
			break;
		}
		if (p != cycle)
			from = to;
		to = *p;
		if (p != cycle) {
			edge = lockdep_find_edge(graph, from, to);
			lockdep_print_edge_info(from, edge);
		}
	}
	free(cycle);
}

static vaddr_t *lockdep_get_kernel_stack(void)
{
	if (IS_ENABLED(CFG_LOCKDEP_RECORD_STACK))
		return unw_get_kernel_stack();

	return NULL;
}

TEE_Result __lockdep_lock_acquire(struct lockdep_node_head *graph,
				  struct lockdep_lock_head *owned,
				  uintptr_t id)
{
	struct lockdep_node *node = lockdep_add_to_graph(graph, id);
	struct lockdep_lock *lock = NULL;
	TEE_Result res = TEE_SUCCESS;
	vaddr_t *acq_stack = NULL;

	if (!node)
		return TEE_ERROR_OUT_OF_MEMORY;

	acq_stack = lockdep_get_kernel_stack();

	TAILQ_FOREACH(lock, owned, link) {
		res = lockdep_add_edge(lock->node, node, lock->call_stack,
				       acq_stack, (uintptr_t)owned);
		if (res)
			return res;
	}

	res = lockdep_graph_sort(graph);
	if (res) {
		EMSG_RAW("Potential deadlock detected!");
		EMSG_RAW("When trying to acquire lock %#" PRIxPTR, id);
		lockdep_print_cycle_info(graph, node);
		return res;
	}

	lock = calloc(1, sizeof(*lock));
	if (!lock)
		return TEE_ERROR_OUT_OF_MEMORY;

	lock->node = node;
	lock->call_stack = acq_stack;
	TAILQ_INSERT_TAIL(owned, lock, link);

	return TEE_SUCCESS;
}

/*
 * Call this when it is known that the thread has been able to acquire the lock.
 * Similar to __lockdep_lock_acquire(), but since the operation is non-blocking,
 * no dependency to currently owned locks are created.
 */
TEE_Result __lockdep_lock_tryacquire(struct lockdep_node_head *graph,
				     struct lockdep_lock_head *owned,
				     uintptr_t id)
{
	struct lockdep_node *node = lockdep_add_to_graph(graph, id);
	struct lockdep_lock *lock = NULL;
	vaddr_t *acq_stack = NULL;

	if (!node)
		return TEE_ERROR_OUT_OF_MEMORY;

	acq_stack = lockdep_get_kernel_stack();

	lock = calloc(1, sizeof(*lock));
	if (!lock)
		return TEE_ERROR_OUT_OF_MEMORY;

	lock->node = node;
	lock->call_stack = acq_stack;
	TAILQ_INSERT_TAIL(owned, lock, link);

	return TEE_SUCCESS;
}

TEE_Result __lockdep_lock_release(struct lockdep_lock_head *owned, uintptr_t id)
{
	struct lockdep_lock *lock = NULL;

	TAILQ_FOREACH_REVERSE(lock, owned, lockdep_lock_head, link) {
		if (lock->node->lock_id == id) {
			TAILQ_REMOVE(owned, lock, link);
			free(lock->call_stack);
			free(lock);
			return TEE_SUCCESS;
		}
	}

	EMSG_RAW("Thread %p does not own lock %#" PRIxPTR, (void *)owned, id);
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static void lockdep_free_edge(struct lockdep_edge *edge)
{
	free(edge->call_stack_from);
	free(edge->call_stack_to);
	free(edge);
}

static void lockdep_node_delete(struct lockdep_node *node)
{
	struct lockdep_edge *edge = NULL;
	struct lockdep_edge *next = NULL;

	STAILQ_FOREACH_SAFE(edge, &node->edges, link, next)
		lockdep_free_edge(edge);

	free(node);
}

void lockdep_graph_delete(struct lockdep_node_head *graph)
{
	struct lockdep_node *node = NULL;
	struct lockdep_node *next = NULL;

	TAILQ_FOREACH_SAFE(node, graph, link, next) {
		TAILQ_REMOVE(graph, node, link);
		lockdep_node_delete(node);
	}
}

void lockdep_queue_delete(struct lockdep_lock_head *owned)
{
	struct lockdep_lock *lock = NULL;
	struct lockdep_lock *next = NULL;

	TAILQ_FOREACH_SAFE(lock, owned, link, next) {
		TAILQ_REMOVE(owned, lock, link);
		free(lock);
	}
}

static void lockdep_node_destroy(struct lockdep_node_head *graph,
				 struct lockdep_node *node)
{
	struct lockdep_edge *edge = NULL;
	struct lockdep_edge *next = NULL;
	struct lockdep_node *from = NULL;

	TAILQ_REMOVE(graph, node, link);

	/*
	 * Loop over all nodes in the graph to remove all edges with the
	 * node to remove in the "to" field.
	 */
	TAILQ_FOREACH(from, graph, link) {
		edge = STAILQ_FIRST(&from->edges);
		while (edge && edge->to == node) {
			STAILQ_REMOVE_HEAD(&from->edges, link);
			lockdep_free_edge(edge);
			edge = STAILQ_FIRST(&from->edges);
		}

		if (!edge)
			continue;

		next = STAILQ_NEXT(edge, link);
		while (next) {
			if (next->to == node) {
				STAILQ_REMOVE_AFTER(&from->edges, edge, link);
				lockdep_free_edge(next);
			} else {
				edge = next;
			}
			next = STAILQ_NEXT(edge, link);
		}
	}

	STAILQ_FOREACH_SAFE(edge, &node->edges, link, next)
		lockdep_free_edge(edge);

	free(node);
}

void lockdep_lock_destroy(struct lockdep_node_head *graph, uintptr_t lock_id)
{
	struct lockdep_node *node = NULL;

	assert(graph);
	TAILQ_FOREACH(node, graph, link) {
		if (node->lock_id == lock_id) {
			lockdep_node_destroy(graph, node);
			break;
		}
	}
}
