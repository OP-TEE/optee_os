// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2024, Linaro Limited
 */

#include <initcall.h>
#include <kernel/mutex.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <optee_rpc_cmd.h>
#include <types_ext.h>

#if defined(CFG_CORE_ASYNC_NOTIF)
struct notif_data {
	bool notif_started;
};

static struct mutex notif_mutex = MUTEX_INITIALIZER;
static unsigned int notif_lock __nex_data = SPINLOCK_UNLOCK;

static struct notif_data default_notif_data;
static unsigned int notif_data_id __nex_bss;

SLIST_HEAD(notif_driver_head, notif_driver);
static struct notif_driver_head notif_driver_head __nex_data =
	SLIST_HEAD_INITIALIZER(&notif_driver_head);

static struct notif_data *get_notif_data(struct guest_partition *prtn)
{
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		assert(prtn);
		return virt_get_guest_spec_data(prtn, notif_data_id);
	}
	return &default_notif_data;
}

bool notif_async_is_started(uint16_t guest_id)
{
	struct guest_partition *prtn = virt_get_guest(guest_id);
	uint32_t old_itr_status = 0;
	bool ret = false;

	if (!IS_ENABLED(CFG_NS_VIRTUALIZATION) || prtn) {
		struct notif_data *ndata = get_notif_data(prtn);

		old_itr_status = cpu_spin_lock_xsave(&notif_lock);
		ret = ndata->notif_started;
		cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
	}

	virt_put_guest(prtn);
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

void notif_deliver_atomic_event(enum notif_event ev, uint16_t guest_id)
{
	struct guest_partition *prtn = virt_get_guest(guest_id);
	struct notif_data *ndata = get_notif_data(prtn);
	struct notif_driver *nd = NULL;
	uint32_t old_itr_status = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	switch (ev) {
	case NOTIF_EVENT_STARTED:
		if (ndata->notif_started) {
			DMSG("Already started");
			goto out;
		}
		ndata->notif_started = true;
		break;
	case NOTIF_EVENT_SHUTDOWN:
		break;
	default:
		EMSG("Unknown event %d", (int)ev);
		panic();
	}

	SLIST_FOREACH(nd, &notif_driver_head, link)
		if (nd->atomic_cb)
			nd->atomic_cb(nd, ev, guest_id);

out:
	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
	virt_put_guest(prtn);
}

void notif_deliver_event(enum notif_event ev)
{
	struct guest_partition *prtn = virt_get_current_guest();
	struct notif_data *ndata = get_notif_data(prtn);
	uint32_t old_itr_status = 0;
	struct notif_driver *nd = NULL;
	struct notif_driver *nd_tmp = NULL;

	assert(ev == NOTIF_EVENT_DO_BOTTOM_HALF || ev == NOTIF_EVENT_STOPPED);

	/* Serialize all yielding notifications */
	mutex_lock(&notif_mutex);
	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	if (!ndata || !ndata->notif_started) {
		DMSG("Not started ev %d", (int)ev);
		goto out;
	}

	if (ev == NOTIF_EVENT_STOPPED)
		ndata->notif_started = false;

	SLIST_FOREACH_SAFE(nd, &notif_driver_head, link, nd_tmp) {
		cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);

		if (nd->yielding_cb)
			nd->yielding_cb(nd, ev);

		old_itr_status = cpu_spin_lock_xsave(&notif_lock);

		if (ev == NOTIF_EVENT_STOPPED && ndata->notif_started) {
			DMSG("Started again while stopping");
			goto out;
		}
	}

out:
	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
	mutex_unlock(&notif_mutex);
	virt_put_guest(prtn);
}

#ifdef CFG_NS_VIRTUALIZATION
static TEE_Result nex_init_notif(void)
{
	return virt_add_guest_spec_data(&notif_data_id,
					sizeof(struct notif_data), NULL);
}
nex_early_init(nex_init_notif);
#endif

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

