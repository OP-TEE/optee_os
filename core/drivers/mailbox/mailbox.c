// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, STMicroelectronics
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/mailbox.h>
#include <drivers/mailbox_device.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <util.h>

/*
 * A channel handle is usable once the mailbox device it refers to is fully
 * registered. Consumers get their handle from the device driver or from the
 * DT, hence a malformed handle is a programming error the API must reject
 * rather than dereference.
 */
static bool mbox_chan_is_valid(const struct mbox_chan *chan)
{
	return chan && chan->mbox_dev && chan->mbox_dev->desc &&
	       chan->mbox_dev->desc->ops;
}

static void mbox_process_cb(const struct mbox_chan *handle, bool notify,
			    uint32_t notify_id, enum mbox_event evt)
{
	if (!handle->cb[evt] && notify) {
		/* Notify the context */
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			notif_send_async(notify_id, 0);
	} else if (handle->cb[evt]) {
		/* Callback consumer function with data */
		handle->cb[evt](handle->cookie);
	}
}

/* Notifier rx callback with consumer data */
static void mbox_rx_callback(struct mbox_chan *chan, void *data)
{
	struct mbox_chan *handle = chan;
	uint32_t exceptions = 0;
	bool notify = false;
	uint32_t notify_id = 0;

	if (!handle) {
		EMSG("Unexpected interrupt");
		return;
	}

	exceptions = cpu_spin_lock_xsave(&handle->lock);
	/* Increase reception count */
	handle->rx_count++;
	if  (handle->rx_done + 1 != handle->rx_count) {
		EMSG("Received Event Not consumed");
		handle->rx_done++;
		assert(handle->rx_done + 1 == handle->rx_count);
	}
	/* Retrieve data */
	handle->data = data;
	notify = handle->notify[MBOX_EVENT_RX];
	notify_id = handle->notify_id[MBOX_EVENT_RX];
	cpu_spin_unlock_xrestore(&handle->lock, exceptions);

	mbox_process_cb(handle, notify, notify_id, MBOX_EVENT_RX);
}

/* Notifier tx callback with consumer data */
static void mbox_tx_callback(struct mbox_chan *chan)
{
	struct mbox_chan *handle = chan;
	uint32_t exceptions = 0;
	bool notify = false;
	uint32_t notify_id = 0;

	if (!handle) {
		EMSG("Unexpected interrupt");
		return;
	}

	exceptions = cpu_spin_lock_xsave(&handle->lock);
	notify = handle->notify[MBOX_EVENT_TX];
	notify_id = handle->notify_id[MBOX_EVENT_TX];
	cpu_spin_unlock_xrestore(&handle->lock, exceptions);

	mbox_process_cb(handle, notify, notify_id, MBOX_EVENT_TX);
}

/* Driver interface */

static TEE_Result mbox_register_internal(struct mbox_dev *mdev,
					 const struct mbox_desc *desc)
{
	const struct mbox_ops *ops = NULL;

	if (!desc || !desc->ops)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Mandatory operations are checked once here so that the consumer API
	 * can call them without testing them on every request.
	 */
	ops = desc->ops;
	if (!ops->send || !ops->max_data_size || !ops->channel_interrupt ||
	    !ops->complete || !ops->capabilities)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Retrieve device capabilities */
	mdev->caps = ops->capabilities(desc->priv);

	/* Fill mdev  */
	mdev->desc = desc;

	return TEE_SUCCESS;
}

TEE_Result mbox_register(struct mbox_dev **mdev,
			 const struct mbox_desc *desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	*mdev = calloc(1, sizeof(**mdev));
	if (!*mdev)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = mbox_register_internal(*mdev, desc);
	if (res)
		free(*mdev);

	return res;
}

/*
 * Shim called by the DT driver framework to translate a consumer "mboxes"
 * specifier into a mailbox channel handle.
 */
#ifdef CFG_DT
static TEE_Result mbox_dt_get_chan(struct dt_pargs *pargs, void *data,
				   void *device_ref)
{
	struct mbox_dev *mdev = data;
	struct mbox_chan **chan = device_ref;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!mdev->desc->ops->get_channel)
		return TEE_ERROR_NOT_SUPPORTED;

	res = mdev->desc->ops->get_channel(mdev->desc->priv, pargs, chan);
	if (res)
		return res;

	if (!*chan)
		return TEE_ERROR_BAD_PARAMETERS;

	(*chan)->mbox_dev = mdev;

	return TEE_SUCCESS;
}

TEE_Result mbox_dt_register(const void *fdt, int nodeoffset,
			    const struct mbox_desc *desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct mbox_dev *mdev = calloc(1, sizeof(*mdev));

	if (!mdev)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = mbox_register_internal(mdev, desc);
	if (res) {
		free(mdev);
		return res;
	}

	res = dt_driver_register_provider(fdt, nodeoffset,
					  mbox_dt_get_chan,
					  (void *)mdev, DT_DRIVER_MAILBOX);
	if (res)
		free(mdev);

	return res;
}
#endif /*CFG_DT*/

static TEE_Result mbox_register_chan_internal(mbox_callback_t rcv_cb,
					      mbox_callback_t txc_cb,
					      void *cookie,
					      struct mbox_chan *chan)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;
	const struct mbox_ops *ops = NULL;
	struct mbox_dev *mbx_dev = NULL;

	/* Check chan */
	if (!mbox_chan_is_valid(chan))
		return TEE_ERROR_BAD_PARAMETERS;
	mbx_dev = chan->mbox_dev;

	/* Check Capability Support */
	if (!(mbx_dev->caps & MBOX_TX_NOTIF_CAP) && txc_cb)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Protect against potential asynchronous event */
	exceptions = cpu_spin_lock_xsave(&chan->lock);

	/* Fill channel mailbox handle */
	chan->cb[MBOX_EVENT_RX] = rcv_cb;
	chan->cb[MBOX_EVENT_TX] = txc_cb;

	chan->cookie = cookie;
	chan->mbox_dev = mbx_dev;

	/*
	 * Without a consumer callback, the blocking flavour of the API relies
	 * on asynchronous notifications. When those are not supported, the
	 * channel is still usable, but only in a non blocking way.
	 */
	if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && !rcv_cb) {
		res = notif_alloc_async_value(&chan->notify_id[MBOX_EVENT_RX]);
		if (res) {
			cpu_spin_unlock_xrestore(&chan->lock,
						 exceptions);
			return res;
		}
	}
	if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && !txc_cb &&
	    (mbx_dev->caps & MBOX_TX_NOTIF_CAP)) {
		res = notif_alloc_async_value(&chan->notify_id[MBOX_EVENT_TX]);
		if (res) {
			cpu_spin_unlock_xrestore(&chan->lock,
						 exceptions);
			return res;
		}
	}
	cpu_spin_unlock_xrestore(&chan->lock, exceptions);

	/* Enable mailbox channel */
	ops = mbx_dev->desc->ops;
	res = ops->channel_interrupt(chan, true);
	if (res) {
		exceptions = cpu_spin_lock_xsave(&chan->lock);
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && !rcv_cb)
			notif_free_async_value(chan->notify_id[MBOX_EVENT_RX]);
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && !txc_cb &&
		    (mbx_dev->caps & MBOX_TX_NOTIF_CAP))
			notif_free_async_value(chan->notify_id[MBOX_EVENT_TX]);
		cpu_spin_unlock_xrestore(&chan->lock,
					 exceptions);
		return res;
	}

	return TEE_SUCCESS;
}

/* Framework API for mailbox device */
void mbox_tx_done(struct mbox_chan *handle)
{
	mbox_tx_callback(handle);
}

void mbox_rx_data(struct mbox_chan *handle,  void *data)
{
	mbox_rx_callback(handle, data);
}

/* Framework API for mailbox user */
#ifdef CFG_DT
TEE_Result mbox_dt_register_chan_by_index(mbox_callback_t rcv_cb,
					  mbox_callback_t txc_cb, void *cookie,
					  const void *fdt, int node,
					  unsigned int index,
					  struct mbox_chan **chan)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!fdt || !chan)
		return TEE_ERROR_BAD_PARAMETERS;

	res = dt_driver_device_from_node_idx_prop("mboxes", fdt, node, index,
						  DT_DRIVER_MAILBOX, chan);
	if (res)
		return res;

	return mbox_register_chan_internal(rcv_cb, txc_cb, cookie, *chan);
}

TEE_Result mbox_dt_register_chan_by_name(mbox_callback_t rcv_cb,
					 mbox_callback_t txc_cb,
					 void *cookie, const void *fdt,
					 int node, const char *name,
					 struct mbox_chan **chan)
{
	int idx = 0;

	if (!fdt || !name || !chan)
		return TEE_ERROR_BAD_PARAMETERS;

	idx = fdt_stringlist_search(fdt, node, "mbox-names", name);
	if (idx < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return  mbox_dt_register_chan_by_index(rcv_cb, txc_cb, cookie, fdt,
					       node, idx, chan);
}
#endif /*CFG_DT*/

TEE_Result mbox_register_chan(mbox_callback_t rcv_cb,
			      mbox_callback_t txc_cb, void *cookie,
			      struct mbox_chan *chan)
{
	return mbox_register_chan_internal(rcv_cb, txc_cb, cookie,
					   chan);
}

TEE_Result mbox_data_max_size(const struct mbox_chan *handle, size_t *size)
{
	const struct mbox_ops *ops = NULL;

	if (!mbox_chan_is_valid(handle) || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	ops = handle->mbox_dev->desc->ops;
	*size = ops->max_data_size(handle);

	return TEE_SUCCESS;
}

TEE_Result mbox_send(const struct mbox_chan *handle, bool wait,
		     const void *data, size_t size)
{
	struct mbox_chan *hdl = (struct mbox_chan *)handle;
	const struct mbox_ops *ops = NULL;
	uint32_t except = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!mbox_chan_is_valid(handle))
		return TEE_ERROR_BAD_PARAMETERS;

	ops = hdl->mbox_dev->desc->ops;

	if (wait) {
		if (!IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			return TEE_ERROR_NOT_SUPPORTED;

		if (!(hdl->mbox_dev->caps & MBOX_TX_NOTIF_CAP))
			return TEE_ERROR_NOT_SUPPORTED;

		if (hdl->cb[MBOX_EVENT_TX])
			return TEE_ERROR_BAD_PARAMETERS;
	}

	if (ops->max_data_size(handle) < size)
		return TEE_ERROR_EXCESS_DATA;

	except = cpu_spin_lock_xsave(&hdl->lock);
	if (hdl->notify[MBOX_EVENT_TX]) {
		cpu_spin_unlock_xrestore(&hdl->lock, except);
		EMSG("Unexpected simultaneous send on a channel");
		return TEE_ERROR_ACCESS_CONFLICT;
	}
	if (wait)
		hdl->notify[MBOX_EVENT_TX] = true;

	cpu_spin_unlock_xrestore(&hdl->lock, except);
	res = ops->send(handle, data, size);
	if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && wait) {
		if (!res)
			notif_wait(hdl->notify_id[MBOX_EVENT_TX]);
		except = cpu_spin_lock_xsave(&hdl->lock);
		hdl->notify[MBOX_EVENT_TX] = false;
		cpu_spin_unlock_xrestore(&hdl->lock, except);
	}

	return res;
}

TEE_Result mbox_recv(const struct mbox_chan *handle, bool wait,
		     void *data, size_t size)
{
	struct mbox_chan *hdl = (struct mbox_chan *)handle;
	const struct mbox_ops *ops = NULL;
	uint32_t except = 0;
	void *copy_data = NULL;
	vaddr_t s = 0;

	if (!mbox_chan_is_valid(handle))
		return TEE_ERROR_BAD_PARAMETERS;

	ops = hdl->mbox_dev->desc->ops;

	if (wait) {
		if (!IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			return TEE_ERROR_NOT_SUPPORTED;

		if (hdl->cb[MBOX_EVENT_RX])
			return TEE_ERROR_BAD_PARAMETERS;
	}

	if (ops->max_data_size(hdl) < size)
		return TEE_ERROR_EXCESS_DATA;

	if ((size && !data) ||
	    (data && size && ADD_OVERFLOW((vaddr_t)data, size, &s)))
		return TEE_ERROR_BAD_PARAMETERS;

	except = cpu_spin_lock_xsave(&hdl->lock);
	if (hdl->notify[MBOX_EVENT_RX]) {
		cpu_spin_unlock_xrestore(&hdl->lock, except);
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	if (hdl->rx_count == hdl->rx_done) {
		if (!IS_ENABLED(CFG_CORE_ASYNC_NOTIF) || !wait) {
			cpu_spin_unlock_xrestore(&hdl->lock, except);
			return TEE_ERROR_NO_DATA;
		}
		hdl->notify[MBOX_EVENT_RX] = true;
		cpu_spin_unlock_xrestore(&hdl->lock, except);
		notif_wait(hdl->notify_id[MBOX_EVENT_RX]);
		except = cpu_spin_lock_xsave(&hdl->lock);
		hdl->notify[MBOX_EVENT_RX] = false;
	}

	if (size && !hdl->data) {
		cpu_spin_unlock_xrestore(&hdl->lock, except);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	copy_data = hdl->data;
	hdl->data = NULL;
	hdl->rx_done++;
	cpu_spin_unlock_xrestore(&hdl->lock, except);
	if (size)
		memcpy(data, copy_data, size);
	/* Acknowledge receive interrupt */
	ops->complete(hdl);

	return TEE_SUCCESS;
}
