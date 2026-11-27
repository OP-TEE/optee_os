// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#include <drivers/rpmi_mailbox.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <sbi.h>
#include <stdlib.h>
#include <util.h>

#include "sbi_mpxy_rpmi_private.h"

/* Mailbox adapter for a discovered RPMI channel. */
struct mpxy_mailbox_channel {
	struct mbox_chan chan;
	struct sbi_mpxy_rpmi_channel *rpmi;
};

static struct mpxy_mailbox_channel *channels;
static struct mbox_controller controller;
static int controller_node = -1;

/* Return an RPMI mailbox attribute from the discovered channel cache. */
static TEE_Result mpxy_get_attribute(struct sbi_mpxy_rpmi_channel *channel,
				     struct rpmi_mbox_message *msg)
{
	TEE_Result res = TEE_SUCCESS;

	switch (msg->attr.id) {
	case RPMI_MBOX_ATTR_SPEC_VERSION:
		msg->attr.value = channel->attrs.msg_proto_version;
		break;
	case RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE:
		msg->attr.value = channel->max_xfer_len;
		break;
	case RPMI_MBOX_ATTR_SERVICEGROUP_ID:
		msg->attr.value = channel->rpmi_attrs.servicegroup_id;
		break;
	case RPMI_MBOX_ATTR_SERVICEGROUP_VERSION:
		msg->attr.value = channel->rpmi_attrs.servicegroup_version;
		break;
	case RPMI_MBOX_ATTR_IMPL_ID:
		msg->attr.value = channel->rpmi_attrs.implementation_id;
		break;
	case RPMI_MBOX_ATTR_IMPL_VERSION:
		msg->attr.value = channel->rpmi_attrs.implementation_version;
		break;
	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

/* Validate and execute an RPMI mailbox message through SBI MPXY. */
static TEE_Result mpxy_send(struct mbox_chan *chan, void *message)
{
	struct mpxy_mailbox_channel *mbox =
		container_of(chan, struct mpxy_mailbox_channel, chan);
	struct sbi_mpxy_rpmi_channel *channel = mbox->rpmi;
	struct rpmi_mbox_message *msg = message;
	unsigned long response_len = 0;
	TEE_Result res = TEE_SUCCESS;
	int rc = 0;

	msg->error = TEE_SUCCESS;

	switch (msg->type) {
	case RPMI_MBOX_MSG_TYPE_GET_ATTRIBUTE:
		res = mpxy_get_attribute(channel, msg);
		break;
	case RPMI_MBOX_MSG_TYPE_SEND_WITH_RESPONSE:
		msg->data.out_response_len = 0;
		if ((!msg->data.request && msg->data.request_len) ||
		    (!msg->data.response && msg->data.max_response_len)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			break;
		}

		if (!(channel->attrs.capability &
		      SBI_MPXY_CHAN_CAP_SEND_WITH_RESP)) {
			res = TEE_ERROR_NOT_SUPPORTED;
			break;
		}

		if (msg->data.request_len > channel->max_xfer_len) {
			res = TEE_ERROR_EXCESS_DATA;
			break;
		}

		rc =
		sbi_mpxy_send_message_with_response(channel->channel_id,
						    msg->data.service_id,
						    msg->data.request,
						    msg->data.request_len,
						    msg->data.response,
						    msg->data.max_response_len,
						    &response_len);
		res = sbi_mpxy_to_tee_result(rc);
		/* Check the channel's effective response-size limit. */
		if (!res && response_len > channel->max_xfer_len)
			res = TEE_ERROR_COMMUNICATION;
		if (!res)
			msg->data.out_response_len = response_len;

		break;
	case RPMI_MBOX_MSG_TYPE_SEND_WITHOUT_RESPONSE:
		if (!msg->data.request && msg->data.request_len) {
			res = TEE_ERROR_BAD_PARAMETERS;
			break;
		}

		if (!(channel->attrs.capability &
		      SBI_MPXY_CHAN_CAP_SEND_WITHOUT_RESP)) {
			res = TEE_ERROR_NOT_SUPPORTED;
			break;
		}

		if (msg->data.request_len > channel->max_xfer_len) {
			res = TEE_ERROR_EXCESS_DATA;
			break;
		}

		rc =
		sbi_mpxy_send_message_without_response(channel->channel_id,
						       msg->data.service_id,
						       msg->data.request,
						       msg->data.request_len);
		res = sbi_mpxy_to_tee_result(rc);
		break;
	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	msg->error = res;

	return TEE_SUCCESS;
}

static TEE_Result mpxy_xlate(struct mbox_controller *ctrl __unused,
			     struct dt_pargs *args, struct mbox_chan **chan)
{
	uint32_t i = 0;

	if (args->args_count != 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (args->args[1] != SBI_MPXY_MSGPROTO_RPMI_ID)
		return TEE_ERROR_NOT_SUPPORTED;

	for (i = 0; i < sbi_mpxy_rpmi_ctx->channel_count; i++) {
		if (channels[i].rpmi->channel_id == args->args[0]) {
			*chan = &channels[i].chan;

			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static const struct mbox_controller_ops mpxy_ops = {
	.get_channel = mpxy_xlate,
	.send_data_sync = mpxy_send,
};

static TEE_Result sbi_mpxy_mailbox_probe(const void *fdt, int node,
					 const void *compat_data __unused)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t i = 0;

	if (!(fdt_get_status(fdt, node) & DT_STATUS_OK_SEC))
		return TEE_ERROR_NODE_DISABLED;

	/* Only one MPXY mailbox controller is supported. */
	if (controller_node >= 0)
		return TEE_ERROR_BAD_FORMAT;

	if (fdt_get_dt_driver_cells(fdt, node, DT_DRIVER_MAILBOX) != 2)
		return TEE_ERROR_BAD_FORMAT;

	/* Optional MPXY support must not prevent boot on older firmware. */
	if (!sbi_ext_available(SBI_EXT_MPXY))
		return TEE_ERROR_NODE_DISABLED;

	res = sbi_mpxy_rpmi_probe_channels();
	if (res)
		return res;

	channels = calloc(sbi_mpxy_rpmi_ctx->channel_count, sizeof(*channels));
	if (!channels)
		return TEE_ERROR_OUT_OF_MEMORY;

	controller.ops = &mpxy_ops;
	for (i = 0; i < sbi_mpxy_rpmi_ctx->channel_count; i++) {
		struct sbi_mpxy_rpmi_channel *channel =
			&sbi_mpxy_rpmi_ctx->channels[i];

		channels[i].rpmi = channel;
		channels[i].chan.controller = &controller;
	}

	res = mbox_controller_register_dt(&controller, fdt, node);
	if (res) {
		free(channels);
		channels = NULL;

		return res;
	}

	controller_node = node;

	return TEE_SUCCESS;
}

static const struct dt_device_match sbi_mpxy_mailbox_match_table[] = {
	{ .compatible = "riscv,sbi-mpxy-mbox" },
	{ }
};

DEFINE_DT_DRIVER(sbi_mpxy_mailbox_driver) = {
	.name = "sbi-mpxy-mailbox",
	.type = DT_DRIVER_MAILBOX,
	.match_table = sbi_mpxy_mailbox_match_table,
	.probe = sbi_mpxy_mailbox_probe,
};
