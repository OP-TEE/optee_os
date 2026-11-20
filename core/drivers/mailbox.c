// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#include <drivers/mailbox.h>
#include <kernel/spinlock.h>
#include <libfdt.h>

static TEE_Result mailbox_xlate(struct dt_pargs *args, void *data, void *ref)
{
	struct mbox_controller *controller = data;
	struct mbox_chan **chan = ref;
	TEE_Result res = TEE_SUCCESS;

	res = controller->ops->get_channel(controller, args, chan);
	/* Expect the channel to belong to the same controller. */
	if (!res && (!*chan || (*chan)->controller != controller))
		return TEE_ERROR_BAD_STATE;

	return res;
}

TEE_Result mbox_controller_register_dt(struct mbox_controller *controller,
				       const void *fdt, int node)
{
	if (!fdt || node < 0 || !controller ||
	    !controller->ops ||
	    !controller->ops->get_channel ||
	    !controller->ops->send_data_sync)
		return TEE_ERROR_BAD_PARAMETERS;

	controller->lock = SPINLOCK_UNLOCK;

	return dt_driver_register_provider(fdt, node, mailbox_xlate, controller,
					   DT_DRIVER_MAILBOX);
}

TEE_Result mbox_request_channel(const void *fdt, int node, unsigned int index,
				struct mbox_client *client,
				struct mbox_chan **chan)
{
	struct mbox_chan *mbox_chan = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;

	if (!fdt || !client || !chan)
		return TEE_ERROR_BAD_PARAMETERS;

	*chan = NULL;

	res = dt_driver_device_from_node_idx_prop("mboxes", fdt, node,
						  index, DT_DRIVER_MAILBOX,
						  &mbox_chan);
	if (res)
		return res;

	/* Assign channel ownership to the client under the controller lock. */
	exceptions = cpu_spin_lock_xsave(&mbox_chan->controller->lock);
	if (mbox_chan->client)
		res = TEE_ERROR_BUSY;
	else
		mbox_chan->client = client;
	cpu_spin_unlock_xrestore(&mbox_chan->controller->lock, exceptions);
	if (!res)
		*chan = mbox_chan;

	return res;
}

TEE_Result mbox_request_channel_byname(const void *fdt, int node,
				       const char *name,
				       struct mbox_client *client,
				       struct mbox_chan **chan)
{
	int index = 0;

	if (!fdt || !name || !chan || !client)
		return TEE_ERROR_BAD_PARAMETERS;

	*chan = NULL;

	index = fdt_stringlist_search(fdt, node, "mbox-names", name);
	if (index < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return mbox_request_channel(fdt, node, index, client, chan);
}

void mbox_free_channel(struct mbox_chan *chan)
{
	uint32_t exceptions = 0;

	if (!chan)
		return;

	exceptions = cpu_spin_lock_xsave(&chan->controller->lock);
	chan->client = NULL;
	cpu_spin_unlock_xrestore(&chan->controller->lock, exceptions);
}

TEE_Result mbox_send_message_sync(struct mbox_chan *chan, void *message)
{
	if (!chan || !chan->client || !message)
		return TEE_ERROR_BAD_PARAMETERS;

	return chan->controller->ops->send_data_sync(chan, message);
}
