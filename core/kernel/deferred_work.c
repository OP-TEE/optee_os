// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <kernel/deferred_work.h>
#include <kernel/spinlock.h>
#include <sys/queue.h>
#include <string.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#define DW_NAME_MAX 32

struct deferred_work {
	TAILQ_ENTRY(deferred_work) link;
	char name[DW_NAME_MAX];
	TEE_Result (*work)(void *data);
	void *data;
};

static unsigned int dw_lock = SPINLOCK_UNLOCK;
static TAILQ_HEAD(dw_queue, deferred_work) head = TAILQ_HEAD_INITIALIZER(head);

TEE_Result deferred_work_add(const char *name, TEE_Result (*work)(void *data),
			     void *data)
{
	size_t n;
	uint32_t exceptions;
	struct deferred_work *new_dw;

	if (!name) {
		EMSG("unnamed work isn't allowed");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!work) {
		EMSG("<null> work-function (work <%s>) isn't allowed", name);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	new_dw = calloc(1, sizeof(struct deferred_work));
	if (!new_dw) {
		EMSG("calloc() failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	n = strlen(name);
	memcpy(new_dw->name, name, n > DW_NAME_MAX - 1 ? DW_NAME_MAX - 1 : n);
	new_dw->work = work;
	new_dw->data = data;

	exceptions = cpu_spin_lock_xsave(&dw_lock);
	TAILQ_INSERT_TAIL(&head, new_dw, link);
	cpu_spin_unlock_xrestore(&dw_lock, exceptions);

	return TEE_SUCCESS;
}

TEE_Result deferred_work_do_all(void)
{
	uint32_t exceptions;
	struct deferred_work *dw;

	exceptions = cpu_spin_lock_xsave(&dw_lock);
	while (!TAILQ_EMPTY(&head)) {
		dw = TAILQ_FIRST(&head);
		TAILQ_REMOVE(&head, dw, link);
		cpu_spin_unlock_xrestore(&dw_lock, exceptions);

		if (dw->work) {
			TEE_Result res;

			res = dw->work(dw->data);
			if (res != TEE_SUCCESS)
				EMSG("dw <%s> failed with code 0x%x", dw->name,
				     res);
			else
				IMSG("dw <%s> successfully finished", dw->name);
		}
		free(dw);

		exceptions = cpu_spin_lock_xsave(&dw_lock);
	}
	cpu_spin_unlock_xrestore(&dw_lock, exceptions);

	return TEE_SUCCESS;
}
