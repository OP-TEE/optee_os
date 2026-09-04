// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, STMicroelectronics
 */

#include <compiler.h>
#include <drivers/mailbox.h>
#include <drivers/mailbox_controller.h>
#include <kernel/spinlock.h>
#include <stdint.h>
#include <stdlib.h>
#include <util.h>

/*
 * struct mbox_controller - Registered mailbox controller
 * @desc: Mailbox controller descriptor
 */
struct mbox_controller {
	const struct mbox_controller_desc *desc;
};

/*
 * A channel handle is usable once the controller it refers to is fully
 * registered. Consumers get their handle from the device driver or from the
 * DT, hence a malformed handle is a programming error the API must reject
 * rather than dereference.
 */
static bool mbox_chan_is_valid(const struct mbox_chan *chan)
{
	return chan && chan->controller && chan->controller->desc &&
	       chan->controller->desc->ops;
}

/*
 * Transfers are only allowed on a channel granted to a consumer. The flag is
 * read without the lock: releasing a channel while a transfer is in progress
 * on it is a consumer error.
 */
static TEE_Result mbox_chan_check_transfer(const struct mbox_chan *chan,
					   void *req)
{
	if (!mbox_chan_is_valid(chan) || !req)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!chan->requested)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

/* Driver interface */

static TEE_Result mbox_controller_register_internal(
					struct mbox_controller *controller,
					const struct mbox_controller_desc *desc)
{
	const struct mbox_controller_ops *ops = NULL;

	if (!desc || !desc->ops)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Mandatory operations are checked once here so that the consumer API
	 * can call them without testing them on every request.
	 */
	ops = desc->ops;
	if (!ops->request_channel || !ops->send_sync)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Fill controller */
	controller->desc = desc;

	return TEE_SUCCESS;
}

TEE_Result mbox_controller_register(struct mbox_controller **controller,
				    const struct mbox_controller_desc *desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	*controller = calloc(1, sizeof(**controller));
	if (!*controller)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = mbox_controller_register_internal(*controller, desc);
	if (res) {
		free(*controller);
		*controller = NULL;
	}

	return res;
}

void *mbox_controller_get_priv(const struct mbox_controller *controller)
{
	return controller->desc->priv;
}

TEE_Result mbox_request_channel(struct mbox_controller *controller,
				const uint32_t *args, size_t args_count,
				struct mbox_chan **chan)
{
	const struct mbox_controller_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;
	bool busy = false;

	if (!controller || !controller->desc || !controller->desc->ops ||
	    (args_count && !args) || !chan)
		return TEE_ERROR_BAD_PARAMETERS;

	ops = controller->desc->ops;
	*chan = NULL;
	res = ops->request_channel(controller, args, args_count, chan);
	if (res)
		return res;

	if (!*chan)
		return TEE_ERROR_BAD_STATE;

	exceptions = cpu_spin_lock_xsave(&(*chan)->lock);
	busy = (*chan)->requested;
	if (!busy) {
		(*chan)->requested = true;
		(*chan)->controller = controller;
	}
	cpu_spin_unlock_xrestore(&(*chan)->lock, exceptions);

	if (busy) {
		*chan = NULL;
		return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

void mbox_free_channel(struct mbox_chan *chan)
{
	const struct mbox_controller_ops *ops = NULL;
	uint32_t exceptions = 0;
	bool requested = false;

	if (!mbox_chan_is_valid(chan))
		return;

	exceptions = cpu_spin_lock_xsave(&chan->lock);
	requested = chan->requested;
	chan->requested = false;
	cpu_spin_unlock_xrestore(&chan->lock, exceptions);

	if (!requested)
		return;

	ops = chan->controller->desc->ops;
	if (ops->free_channel)
		ops->free_channel(chan);
}

TEE_Result mbox_send_sync(const struct mbox_chan *handle, void *req)
{
	TEE_Result res = mbox_chan_check_transfer(handle, req);

	if (res)
		return res;

	return handle->controller->desc->ops->send_sync(handle, req);
}

TEE_Result mbox_recv_sync(const struct mbox_chan *handle, void *req)
{
	const struct mbox_controller_ops *ops = NULL;
	TEE_Result res = mbox_chan_check_transfer(handle, req);

	if (res)
		return res;

	ops = handle->controller->desc->ops;
	if (!ops->recv_sync)
		return TEE_ERROR_NOT_SUPPORTED;

	return ops->recv_sync(handle, req);
}
