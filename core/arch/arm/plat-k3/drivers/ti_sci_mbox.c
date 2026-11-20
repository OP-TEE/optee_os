// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 TISCI mailbox controller
 * Glue between the mailbox framework and the TISCI transport (Secure Proxy
 * or K3 mailbox) selected at build time.
 */

#include <drivers/mailbox.h>
#include <drivers/mailbox_controller.h>
#include <stddef.h>
#include <stdint.h>
#include "ti_sci_transport.h"

static struct mbox_chan ti_sci_chan;

static TEE_Result ti_sci_mbox_request_channel(struct mbox_controller *ctrl __unused,
					      const uint32_t *args __unused,
					      size_t args_count,
					      struct mbox_chan **chan)
{
	/* The TISCI transport exposes a single channel without specifier */
	if (args_count)
		return TEE_ERROR_BAD_PARAMETERS;

	*chan = &ti_sci_chan;

	return TEE_SUCCESS;
}

static TEE_Result ti_sci_mbox_send_sync(const struct mbox_chan *chan __unused,
					void *req)
{
	return ti_sci_transport_send(req);
}

static TEE_Result ti_sci_mbox_recv_sync(const struct mbox_chan *chan __unused,
					void *req)
{
	return ti_sci_transport_recv(req);
}

static const struct mbox_controller_ops ti_sci_mbox_ops = {
	.request_channel = ti_sci_mbox_request_channel,
	.send_sync = ti_sci_mbox_send_sync,
	.recv_sync = ti_sci_mbox_recv_sync,
};

static const struct mbox_controller_desc ti_sci_mbox_desc = {
	.ops = &ti_sci_mbox_ops,
};

TEE_Result ti_sci_mbox_init(struct mbox_chan **chan)
{
	struct mbox_controller *ctrl = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = ti_sci_transport_init();
	if (res)
		return res;

	res = mbox_controller_register(&ctrl, &ti_sci_mbox_desc);
	if (res)
		return res;

	return mbox_request_channel(ctrl, NULL, 0, chan);
}
