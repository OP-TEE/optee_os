// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <bitstring.h>
#include <drivers/gic.h>
#include <kernel/interrupt.h>
#include <kernel/mutex.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <optee_rpc_cmd.h>
#include <types_ext.h>

#if defined(CFG_CORE_ASYNC_NOTIF)
static struct mutex notif_mutex = MUTEX_INITIALIZER;
static unsigned int notif_lock = SPINLOCK_UNLOCK;

SLIST_HEAD(notif_driver_head, notif_driver);
static struct notif_driver_head notif_driver_head =
	SLIST_HEAD_INITIALIZER(&notif_driver_head);

static bitstr_t bit_decl(notif_values, NOTIF_ASYNC_VALUE_MAX + 1);
static bitstr_t bit_decl(notif_alloc_values, NOTIF_ASYNC_VALUE_MAX + 1);
static bool notif_started;

TEE_Result notif_alloc_async_value(uint32_t *val)
{
	static bool alloc_values_inited;
	uint32_t old_itr_status = 0;
	int bit = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	if (!alloc_values_inited) {
		bit_set(notif_alloc_values, NOTIF_VALUE_DO_BOTTOM_HALF);
		alloc_values_inited = true;
	}

	bit_ffc(notif_alloc_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	if (bit >= 0) {
		*val = bit;
		bit_set(notif_alloc_values, bit);
	}

	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);

	if (bit < 0)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

void notif_free_async_value(uint32_t val)
{
	uint32_t old_itr_status = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	assert(val < NOTIF_ASYNC_VALUE_MAX);
	assert(bit_test(notif_alloc_values, val));
	bit_clear(notif_alloc_values, val);

	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
}

uint32_t notif_get_value(bool *value_valid, bool *value_pending)
{
	uint32_t old_itr_status = 0;
	uint32_t res = 0;
	int bit = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	bit_ffs(notif_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	*value_valid = (bit >= 0);
	if (!*value_valid) {
		*value_pending = false;
		goto out;
	}

	res = bit;
	bit_clear(notif_values, res);
	bit_ffs(notif_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	*value_pending = (bit >= 0);
out:
	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);

	return res;
}

void notif_send_async(uint32_t value)
{
	uint32_t old_itr_status = 0;

	COMPILE_TIME_ASSERT(CFG_CORE_ASYNC_NOTIF_GIC_INTID >= GIC_SPI_BASE);

	assert(value <= NOTIF_ASYNC_VALUE_MAX);
	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	DMSG("0x%"PRIx32, value);
	bit_set(notif_values, value);
	itr_raise_pi(CFG_CORE_ASYNC_NOTIF_GIC_INTID);

	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
}

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

static TEE_Result notif_rpc(uint32_t func, uint32_t value)
{
	struct thread_param params = THREAD_PARAM_VALUE(IN, func, value, 0);

	return thread_rpc_cmd(OPTEE_RPC_CMD_NOTIFICATION, 1, &params);
}

TEE_Result notif_wait(uint32_t value)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_WAIT, value);
}

TEE_Result notif_send_sync(uint32_t value)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_SEND, value);
}
