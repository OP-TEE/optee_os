// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2023, Linaro Limited
 */

#include <kernel/mutex.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <optee_rpc_cmd.h>
#include <types_ext.h>

#if defined(CFG_CORE_ASYNC_NOTIF)
static struct mutex notif_mutex = MUTEX_INITIALIZER;
static unsigned int notif_lock __nex_data = SPINLOCK_UNLOCK;
static bool notif_started;

SLIST_HEAD(notif_driver_head, notif_driver);
static struct notif_driver_head notif_driver_head __nex_data =
	SLIST_HEAD_INITIALIZER(&notif_driver_head);


bool notif_async_is_started(void)
{
	uint32_t old_itr_status = 0;
	bool ret = false;

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);
	ret = notif_started;
	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);

	return ret;
}

void notif_register_driver(struct notif_driver *ndrv)
{
	uint32_t old_itr_status = 0;

	assert(is_nexus(ndrv) && is_unpaged(ndrv->atomic_cb));

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	SLIST_INSERT_HEAD(&notif_driver_head, ndrv, link);

	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
}

void notif_unregister_driver(struct notif_driver *ndrv)
{
	uint32_t old_itr_status = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	SLIST_REMOVE(&notif_driver_head, ndrv, notif_driver, link);

	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
}

void notif_deliver_atomic_event(enum notif_event ev)
{
	uint32_t old_itr_status = 0;
	struct notif_driver *nd = NULL;

	assert(ev == NOTIF_EVENT_STARTED);

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	if (notif_started) {
		DMSG("Already started");
		goto out;
	}
	notif_started = true;

	SLIST_FOREACH(nd, &notif_driver_head, link)
		if (nd->atomic_cb)
			nd->atomic_cb(nd, ev);

out:
	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
}

void notif_deliver_event(enum notif_event ev)
{
	uint32_t old_itr_status = 0;
	struct notif_driver *nd = NULL;
	struct notif_driver *nd_tmp = NULL;

	assert(ev == NOTIF_EVENT_DO_BOTTOM_HALF || ev == NOTIF_EVENT_STOPPED);

	/* Serialize all yielding notifications */
	mutex_lock(&notif_mutex);
	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	if (!notif_started) {
		DMSG("Not started ev %d", (int)ev);
		goto out;
	}

	if (ev == NOTIF_EVENT_STOPPED)
		notif_started = false;

	SLIST_FOREACH_SAFE(nd, &notif_driver_head, link, nd_tmp) {
		cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);

		if (nd->yielding_cb)
			nd->yielding_cb(nd, ev);

		old_itr_status = cpu_spin_lock_xsave(&notif_lock);

		if (ev == NOTIF_EVENT_STOPPED && notif_started) {
			DMSG("Started again while stopping");
			goto out;
		}
	}

out:
	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
	mutex_unlock(&notif_mutex);
}
#endif /*CFG_CORE_ASYNC_NOTIF*/

static TEE_Result notif_rpc(uint32_t func, uint32_t value1, uint32_t value2)
{
	struct thread_param params =
		THREAD_PARAM_VALUE(IN, func, value1, value2);

	return thread_rpc_cmd(OPTEE_RPC_CMD_NOTIFICATION, 1, &params);
}

TEE_Result notif_wait(uint32_t value)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_WAIT, value, 0);
}

TEE_Result notif_send_sync(uint32_t value)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_SEND, value, 0);
}

TEE_Result notif_wait_timeout(uint32_t value, uint32_t timeout_ms)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_WAIT, value, timeout_ms);
}
