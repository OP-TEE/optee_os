// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2023, Linaro Limited
 */

#include <bitstring.h>
#include <confine_array_index.h>
#include <drivers/gic.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/mutex.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <optee_rpc_cmd.h>
#include <sm/optee_smc.h>
#include <stdint.h>
#include <string.h>
#include <types_ext.h>

/*
 * Notification of non-secure interrupt events identified by an IT number
 * from 0 to CFG_CORE_ITR_NOTIF_MAX.
 */
#define NOTIF_ITR_VALUE_MAX		CFG_CORE_ITR_NOTIF_MAX

#if defined(CFG_CORE_ASYNC_NOTIF)
static struct mutex notif_mutex = MUTEX_INITIALIZER;
static unsigned int notif_lock = SPINLOCK_UNLOCK;

SLIST_HEAD(notif_driver_head, notif_driver);
static struct notif_driver_head notif_driver_head =
	SLIST_HEAD_INITIALIZER(&notif_driver_head);

static bitstr_t bit_decl(notif_values, NOTIF_ASYNC_VALUE_MAX + 1);
static bitstr_t bit_decl(notif_alloc_values, NOTIF_ASYNC_VALUE_MAX + 1);
static bool notif_started;

#if defined(CFG_CORE_ITR_NOTIF)
static bitstr_t bit_decl(notif_itr_pending, NOTIF_ITR_VALUE_MAX + 1);
static bitstr_t bit_decl(notif_itr_masked, NOTIF_ITR_VALUE_MAX + 1);

static unsigned int notif_itr_lock = SPINLOCK_UNLOCK;
static struct notif_itr *notif_itr_handler[NOTIF_ITR_VALUE_MAX + 1];
#endif

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

	static_assert(CFG_CORE_ASYNC_NOTIF_GIC_INTID >= GIC_PPI_BASE);

	assert(value <= NOTIF_ASYNC_VALUE_MAX);
	old_itr_status = cpu_spin_lock_xsave(&notif_lock);

	DMSG("0x%"PRIx32, value);
	bit_set(notif_values, value);
	itr_raise_pi(CFG_CORE_ASYNC_NOTIF_GIC_INTID);

	cpu_spin_unlock_xrestore(&notif_lock, old_itr_status);
}

#if defined(CFG_CORE_ITR_NOTIF)
static int get_pending_itr_num(int start_bit)
{
	const int max_bit = NOTIF_ITR_VALUE_MAX + 1;
	int bit = start_bit - 1;

	do {
		bit_ffs_from(notif_itr_pending, max_bit, bit + 1, &bit);
	} while (bit >= 0 && bit_test(notif_itr_masked, bit));

	return bit;
}

void notif_get_pending(bool *do_bottom_half, bool *value_pending,
		       uint16_t *itr_nums, size_t *itr_count)
{
	uint32_t exceptions = 0;
	bool do_bh = false;
	size_t count = 0;
	int bit = 0;

	exceptions = cpu_spin_lock_xsave(&notif_itr_lock);

	/* Retrieve at most *itr_num's pending event */
	for (count = 0; count < *itr_count; count++) {
		bit = get_pending_itr_num(bit);
		if (bit < 0)
			break;

		bit_clear(notif_itr_pending, bit);
		itr_nums[count] = bit;
	}

	/* Report if there are other pending interrupts */
	if (count == *itr_count && get_pending_itr_num(0) >= 0)
		count++;

	/* Retrieve bottom half event if pending */
	if (bit_test(notif_values, NOTIF_VALUE_DO_BOTTOM_HALF)) {
		bit_clear(notif_values, NOTIF_VALUE_DO_BOTTOM_HALF);
		do_bh = true;
	}

	/* Report if there are pending async notif other than do bottom half */
	bit_ffs_from(notif_values, NOTIF_VALUE_DO_BOTTOM_HALF + 1,
		     (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);

	cpu_spin_unlock_xrestore(&notif_itr_lock, exceptions);

	*itr_count = count;
	*value_pending = (bit >= 0);
	*do_bottom_half = do_bh;
}

/* This function can execute in a fastcall interrupt masked context */
static void set_itr_mask(unsigned int itr_num, bool do_mask)
{
	uint32_t exceptions = 0;

	if (itr_num > NOTIF_ITR_VALUE_MAX)
		return;

	FMSG("Itr notif %u %smasked", itr_num, do_mask ? "" : "un");

	exceptions = cpu_spin_lock_xsave(&notif_itr_lock);

	if (do_mask) {
		bit_set(notif_itr_masked, itr_num);
	} else {
		bit_clear(notif_itr_masked, itr_num);

		if (bit_test(notif_itr_pending, itr_num))
			itr_raise_pi(CFG_CORE_ASYNC_NOTIF_GIC_INTID);
	}

	cpu_spin_unlock_xrestore(&notif_itr_lock, exceptions);
}

static struct notif_itr __maybe_unused *find_notif_itr(unsigned int itr_num)
{
	assert(itr_num <= NOTIF_ITR_VALUE_MAX);
	return notif_itr_handler[itr_num];
}

static struct notif_itr *find_notif_itr_safe(unsigned int itr_num)
{
	/* Sanitize interrupt identifier provided by normal world */
	if (itr_num > NOTIF_ITR_VALUE_MAX)
		return NULL;
	itr_num = confine_array_index(itr_num, NOTIF_ITR_VALUE_MAX + 1);

	return notif_itr_handler[itr_num];
}

static void remove_notif_itr_handler(struct notif_itr *notif)
{
	assert(notif && notif->itr_num <= NOTIF_ITR_VALUE_MAX &&
	       notif_itr_handler[notif->itr_num] == notif);

	notif_itr_handler[notif->itr_num] = NULL;
}

static void add_notif_itr_handler(struct notif_itr *notif)
{
	assert(notif && notif->itr_num <= NOTIF_ITR_VALUE_MAX &&
	       !notif_itr_handler[notif->itr_num]);

	notif_itr_handler[notif->itr_num] = notif;
}

void notif_itr_set_mask(unsigned int itr_num, bool do_mask)
{
	struct notif_itr *notif = find_notif_itr_safe(itr_num);

	if (notif) {
		set_itr_mask(itr_num, do_mask);
		if (notif->ops && notif->ops->set_mask)
			notif->ops->set_mask(notif, do_mask);
	}
}

TEE_Result notif_itr_set_state(unsigned int itr_num, bool do_enable)
{
	struct notif_itr *notif = find_notif_itr_safe(itr_num);

	if (!notif)
		return TEE_ERROR_BAD_PARAMETERS;

	set_itr_mask(itr_num, !do_enable);

	if (notif->ops && notif->ops->set_state)
		return notif->ops->set_state(notif, do_enable);

	/* Notifier may not implement set_state */
	return TEE_SUCCESS;
}

TEE_Result notif_itr_set_wakeup(unsigned int itr_num, bool do_enable)
{
	struct notif_itr *notif = find_notif_itr_safe(itr_num);

	if (!notif)
		return TEE_ERROR_BAD_PARAMETERS;

	if (notif->ops && notif->ops->set_wakeup)
		return notif->ops->set_wakeup(notif, do_enable);

	/* Notifier must implement set_wakeup for a wakeup source interrupt */
	return TEE_ERROR_NOT_SUPPORTED;
}

void notif_itr_raise_event(struct notif_itr *notif)
{
	uint32_t exceptions = 0;

	assert(find_notif_itr(notif->itr_num) == notif);

	exceptions = cpu_spin_lock_xsave(&notif_itr_lock);

	bit_set(notif_itr_pending, notif->itr_num);

	if (!bit_test(notif_itr_masked, notif->itr_num))
		itr_raise_pi(CFG_CORE_ASYNC_NOTIF_GIC_INTID);

	cpu_spin_unlock_xrestore(&notif_itr_lock, exceptions);
}

TEE_Result notif_itr_register(struct notif_itr *notif)
{
	unsigned int itr_num = 0;
	uint32_t exceptions = 0;
	const struct notif_itr_ops __maybe_unused *ops = NULL;

	assert(notif && is_unpaged(notif));
	itr_num = notif->itr_num;
	assert(itr_num <= NOTIF_ITR_VALUE_MAX && !find_notif_itr(itr_num));
	ops = notif->ops;
	assert(!ops || (is_unpaged((void *)ops) &&
			(!ops->set_mask || is_unpaged(ops->set_mask))));

	exceptions = cpu_spin_lock_xsave(&notif_itr_lock);
	bit_clear(notif_itr_pending, itr_num);
	cpu_spin_unlock_xrestore(&notif_itr_lock, exceptions);

	set_itr_mask(itr_num, 1);

	add_notif_itr_handler(notif);

	return TEE_SUCCESS;
}

TEE_Result notif_itr_unregister(struct notif_itr *notif)
{
	uint32_t exceptions = 0;

	if (!notif)
		return TEE_SUCCESS;

	assert(find_notif_itr(notif->itr_num) == notif);

	exceptions = cpu_spin_lock_xsave(&notif_lock);
	bit_clear(notif_itr_pending, notif->itr_num);
	bit_set(notif_itr_masked, notif->itr_num);
	cpu_spin_unlock_xrestore(&notif_lock, exceptions);

	remove_notif_itr_handler(notif);

	return TEE_SUCCESS;
}
#endif /*CFG_CORE_ITR_NOTIF*/

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

#if defined(CFG_CORE_ITR_NOTIF)
	old_itr_status = cpu_spin_lock_xsave(&notif_itr_lock);

	bit_nset(notif_itr_masked, 0, (int)NOTIF_ITR_VALUE_MAX);

	cpu_spin_unlock_xrestore(&notif_itr_lock, old_itr_status);
#endif
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
