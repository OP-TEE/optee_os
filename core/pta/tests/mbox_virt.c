// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, STMicroelectronics
 */
#include <config.h>
#include <drivers/mailbox.h>
#include <drivers/mailbox_controller.h>
#include <kernel/mutex.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <string.h>
#include <util.h>

#include "mbox_virt.h"

struct mbox_virt;

struct mbox_virt_chan {
	struct mbox_chan chan;
	struct mbox_virt *virt;
};

struct mbox_virt {
	struct mbox_controller_desc desc;
	struct mbox_controller *ctrl;
	struct mbox_virt_chan chans[MBOX_VIRT_CHAN_COUNT];
	enum mbox_virt_flavor flavor;
	/* Protects slot, slot_full and waiting */
	unsigned int lock;
	struct mbox_virt_msg slot;
	bool slot_full;
	/* A recv_sync is waiting for notif_id (MBOX_VIRT_BLOCKING) */
	bool waiting;
	uint32_t notif_id;
	TEE_Result error;
	struct mbox_virt_stats stats;
};

static struct mbox_virt virt_ctrls[MBOX_VIRT_FLAVOR_COUNT];
/* Serializes the first registration, the blocking tests run concurrently */
static struct mutex virt_mutex = MUTEX_INITIALIZER;

static struct mbox_virt *virt_from_ctrl(const struct mbox_controller *ctrl)
{
	return mbox_controller_get_priv(ctrl);
}

static struct mbox_virt *virt_from_chan(const struct mbox_chan *chan)
{
	return container_of(chan, struct mbox_virt_chan, chan)->virt;
}

static TEE_Result virt_request_channel(struct mbox_controller *ctrl,
				       const uint32_t *args, size_t args_count,
				       struct mbox_chan **chan)
{
	struct mbox_virt *virt = virt_from_ctrl(ctrl);
	uint32_t index = args_count ? args[0] : 0;

	virt->stats.requested++;
	virt->stats.last_args_count = args_count;
	virt->stats.last_arg0 = index;

	switch (virt->flavor) {
	case MBOX_VIRT_NULL_CHAN:
		*chan = NULL;
		break;
	case MBOX_VIRT_FAILING:
		if (virt->error)
			return virt->error;
		fallthrough;
	default:
		if (index >= MBOX_VIRT_CHAN_COUNT)
			return TEE_ERROR_ITEM_NOT_FOUND;
		*chan = &virt->chans[index].chan;
		break;
	}

	return TEE_SUCCESS;
}

static void virt_free_channel(struct mbox_chan *chan)
{
	virt_from_chan(chan)->stats.freed++;
}

static TEE_Result virt_send_sync(const struct mbox_chan *chan, void *req)
{
	struct mbox_virt *virt = virt_from_chan(chan);
	uint32_t exceptions = 0;
	bool notify = false;

	if (virt->flavor == MBOX_VIRT_FAILING && virt->error)
		return virt->error;

	exceptions = cpu_spin_lock_xsave(&virt->lock);
	if (virt->slot_full) {
		cpu_spin_unlock_xrestore(&virt->lock, exceptions);
		return TEE_ERROR_BUSY;
	}

	memcpy(&virt->slot, req, sizeof(virt->slot));
	virt->slot_full = true;
	virt->stats.sent++;
	notify = virt->waiting;
	cpu_spin_unlock_xrestore(&virt->lock, exceptions);

	if (notify)
		notif_send_async(virt->notif_id, 0);

	return TEE_SUCCESS;
}

/* Take the pending message if any, @virt->waiting is set when there is none */
static bool virt_take_msg(struct mbox_virt *virt, void *req, bool wait)
{
	uint32_t exceptions = 0;
	bool taken = false;

	exceptions = cpu_spin_lock_xsave(&virt->lock);
	if (virt->slot_full) {
		memcpy(req, &virt->slot, sizeof(virt->slot));
		virt->slot_full = false;
		virt->stats.received++;
		taken = true;
	}
	virt->waiting = wait && !taken;
	cpu_spin_unlock_xrestore(&virt->lock, exceptions);

	return taken;
}

static TEE_Result virt_recv_sync(const struct mbox_chan *chan, void *req)
{
	struct mbox_virt *virt = virt_from_chan(chan);
	unsigned int polls = MBOX_VIRT_WAIT_MS / MBOX_VIRT_POLL_MS;
	bool wait = virt->flavor == MBOX_VIRT_BLOCKING;

	if (virt->flavor == MBOX_VIRT_FAILING && virt->error)
		return virt->error;

	if (virt_take_msg(virt, req, wait))
		return TEE_SUCCESS;

	if (!wait)
		return TEE_ERROR_NO_DATA;

	/*
	 * Wait in short slices and check the slot again each time: a stale
	 * notification left by a previous wait only causes an early wakeup.
	 */
	while (polls--) {
		notif_wait_timeout(virt->notif_id, MBOX_VIRT_POLL_MS);
		if (virt_take_msg(virt, req, true))
			return TEE_SUCCESS;
	}

	virt_take_msg(virt, req, false);

	return TEE_ERROR_TIMEOUT;
}

static const struct mbox_controller_ops virt_ops_full = {
	.request_channel = virt_request_channel,
	.free_channel = virt_free_channel,
	.send_sync = virt_send_sync,
	.recv_sync = virt_recv_sync,
};

static const struct mbox_controller_ops virt_ops_no_recv = {
	.request_channel = virt_request_channel,
	.free_channel = virt_free_channel,
	.send_sync = virt_send_sync,
};

static const struct mbox_controller_ops virt_ops_no_free = {
	.request_channel = virt_request_channel,
	.send_sync = virt_send_sync,
	.recv_sync = virt_recv_sync,
};

static const struct mbox_controller_ops virt_ops_blocking = {
	.request_channel = virt_request_channel,
	.free_channel = virt_free_channel,
	.send_sync = virt_send_sync,
	.recv_sync = virt_recv_sync,
};

static const struct mbox_controller_ops *virt_ops(enum mbox_virt_flavor flavor)
{
	switch (flavor) {
	case MBOX_VIRT_NO_RECV:
		return &virt_ops_no_recv;
	case MBOX_VIRT_NO_FREE:
		return &virt_ops_no_free;
	case MBOX_VIRT_BLOCKING:
		return &virt_ops_blocking;
	default:
		return &virt_ops_full;
	}
}

TEE_Result mbox_virt_get(enum mbox_virt_flavor flavor,
			 struct mbox_controller **ctrl)
{
	struct mbox_virt *virt = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t n = 0;

	if (flavor >= MBOX_VIRT_FLAVOR_COUNT || !ctrl)
		return TEE_ERROR_BAD_PARAMETERS;

	if (flavor == MBOX_VIRT_BLOCKING && !IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
		return TEE_ERROR_NOT_SUPPORTED;

	virt = &virt_ctrls[flavor];
	mutex_lock(&virt_mutex);
	if (!virt->ctrl) {
		if (flavor == MBOX_VIRT_BLOCKING) {
			res = notif_alloc_async_value(&virt->notif_id);
			if (res)
				goto out;
		}
		virt->flavor = flavor;
		virt->desc.ops = virt_ops(flavor);
		virt->desc.priv = virt;
		for (n = 0; n < MBOX_VIRT_CHAN_COUNT; n++)
			virt->chans[n].virt = virt;
		res = mbox_controller_register(&virt->ctrl, &virt->desc);
		if (res) {
			virt->ctrl = NULL;
			if (flavor == MBOX_VIRT_BLOCKING)
				notif_free_async_value(virt->notif_id);
			goto out;
		}
	}

	*ctrl = virt->ctrl;
	res = TEE_SUCCESS;
out:
	mutex_unlock(&virt_mutex);

	return res;
}

struct mbox_virt_stats *mbox_virt_stats(struct mbox_controller *ctrl)
{
	return &virt_from_ctrl(ctrl)->stats;
}

void mbox_virt_set_error(struct mbox_controller *ctrl, TEE_Result res)
{
	virt_from_ctrl(ctrl)->error = res;
}

void mbox_virt_reset(struct mbox_controller *ctrl)
{
	struct mbox_virt *virt = virt_from_ctrl(ctrl);
	size_t n = 0;

	/* Channels left granted by a previous test case */
	for (n = 0; n < MBOX_VIRT_CHAN_COUNT; n++)
		mbox_free_channel(&virt->chans[n].chan);

	virt->error = TEE_SUCCESS;
	virt->slot_full = false;
	virt->waiting = false;
	memset(&virt->stats, 0, sizeof(virt->stats));
}
