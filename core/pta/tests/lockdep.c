// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

/*
 * Test lockdep with hypothetical thread and lock objects
 */

#include <assert.h>
#include <kernel/lockdep.h>

#include "misc.h"

static int self_test_lockdep1(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct lockdep_node_head graph;
	struct lockdep_lock_head thread1;
	int count = 1;

	DMSG("");

	TAILQ_INIT(&thread1);
	TAILQ_INIT(&graph);

	/* Not locked, expect failure */
	res = __lockdep_lock_release(&thread1, 1);
	if (!res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_release(&thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread1, 3);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread1, 2);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_release(&thread1, 3);
	if (res)
		return count;
	count++;

	/* Already locked */
	res = __lockdep_lock_acquire(&graph, &thread1, 2);
	if (!res)
		return count;

	lockdep_graph_delete(&graph);
	lockdep_queue_delete(&thread1);

	return 0;
}

static int self_test_lockdep2(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct lockdep_node_head graph;
	struct lockdep_lock_head thread1;
	struct lockdep_lock_head thread2;
	struct lockdep_lock_head thread3;
	int count = 1;

	DMSG("");

	TAILQ_INIT(&thread1);
	TAILQ_INIT(&thread2);
	TAILQ_INIT(&thread3);
	TAILQ_INIT(&graph);

	res = __lockdep_lock_acquire(&graph, &thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread2, 2);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread1, 2);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread3, 3);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread2, 3);
	if (res)
		return count;
	count++;

	/* Deadlock 1-2-3 */
	res = __lockdep_lock_acquire(&graph, &thread3, 1);
	if (!res)
		return count;

	lockdep_graph_delete(&graph);
	lockdep_queue_delete(&thread1);
	lockdep_queue_delete(&thread2);
	lockdep_queue_delete(&thread3);

	return 0;
}

static int self_test_lockdep3(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct lockdep_node_head graph;
	struct lockdep_lock_head thread1;
	struct lockdep_lock_head thread2;
	int count = 1;

	DMSG("");

	TAILQ_INIT(&thread1);
	TAILQ_INIT(&thread2);
	TAILQ_INIT(&graph);

	res = __lockdep_lock_tryacquire(&graph, &thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_release(&thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_tryacquire(&graph, &thread1, 1);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread2, 2);
	if (res)
		return count;
	count++;

	res = __lockdep_lock_acquire(&graph, &thread1, 2);
	if (res)
		return count;
	count++;

	/* Deadlock 1-2 */
	res = __lockdep_lock_acquire(&graph, &thread2, 1);
	if (!res)
		return count;

	lockdep_graph_delete(&graph);
	lockdep_queue_delete(&thread1);
	lockdep_queue_delete(&thread2);

	return 0;
}

TEE_Result core_lockdep_tests(uint32_t nParamTypes __unused,
			      TEE_Param pParams[TEE_NUM_PARAMS] __unused)

{
	int count = 0;

	count = self_test_lockdep1();
	if (count)
		goto out;
	count = self_test_lockdep2();
	if (count)
		goto out;
	count = self_test_lockdep3();
	if (count)
		goto out;
out:
	if (count) {
		DMSG("count=%d", count);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
