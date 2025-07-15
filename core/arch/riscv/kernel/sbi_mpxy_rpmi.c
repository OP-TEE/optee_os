// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 NXP
 */

#include <riscv.h>
#include <rpmi.h>
#include <sbi.h>
#include <sbi_mpxy.h>
#include <sbi_mpxy_rpmi.h>
#include <stdlib.h>
#include <string.h>

struct sbi_mpxy_rpmi_context *sbi_mpxy_rpmi_ctx;

/**
 * @brief Probes available MPXY channels supporting the RPMI protocol.
 *
 * This function initializes the global RPMI context by identifying available
 * MPXY channels with the RPMI protocol, reading their attributes, and
 * allocating memory for handling notifications. The result is stored in a
 * global context (sbi_mpxy_rpmi_ctx). If probing fails, the context is set to
 * NULL.
 */
void sbi_mpxy_rpmi_probe_channels(void)
{
	struct sbi_mpxy_rpmi_channel *channel = NULL;
	uint32_t *channel_ids = NULL;
	unsigned long mpxy_shmem_size = 0;
	uint32_t valid_channels = 0;
	uint32_t i = 0;
	int ret = 0;
	uint32_t channel_id = 0;

	if (sbi_mpxy_rpmi_ctx) {
		EMSG("RPMI/MPXY context already initialized");
		return;
	}

	ret = sbi_mpxy_get_shmem_size(&mpxy_shmem_size);
	if (ret) {
		EMSG("Failed to get MPXY shared memory size (ret=%d)", ret);
		goto error;
	}

	sbi_mpxy_rpmi_ctx = calloc(1, sizeof(*sbi_mpxy_rpmi_ctx));
	if (!sbi_mpxy_rpmi_ctx) {
		EMSG("Out of memory for RPMI context");
		goto error;
	}

	ret = sbi_mpxy_get_channel_count(&sbi_mpxy_rpmi_ctx->channel_count);
	if (ret || !sbi_mpxy_rpmi_ctx->channel_count) {
		EMSG("Failed to get MPXY channel count (ret=%d)", ret);
		goto error;
	}

	channel_ids =
		calloc(sbi_mpxy_rpmi_ctx->channel_count, sizeof(*channel_ids));
	if (!channel_ids) {
		EMSG("Failed to allocate channel ID list");
		goto error;
	}

	ret = sbi_mpxy_get_channel_ids(sbi_mpxy_rpmi_ctx->channel_count,
				       channel_ids);
	if (ret) {
		EMSG("Failed to fetch channel IDs (ret=%d)", ret);
		goto error;
	}

	sbi_mpxy_rpmi_ctx->channels =
		calloc(sbi_mpxy_rpmi_ctx->channel_count,
		       sizeof(*sbi_mpxy_rpmi_ctx->channels));
	if (!sbi_mpxy_rpmi_ctx->channels) {
		EMSG("Failed to allocate channel table");
		goto error;
	}

	for (i = 0; i < sbi_mpxy_rpmi_ctx->channel_count; i++) {
		channel_id = channel_ids[i];
		channel = &sbi_mpxy_rpmi_ctx->channels[valid_channels];
		channel->channel_id = channel_id;

		ret = sbi_mpxy_read_attributes(channel_id,
					       SBI_MPXY_ATTR_MSG_PROT_ID,
					       sizeof(channel->attrs) /
						       sizeof(uint32_t),
					       &channel->attrs);
		if (ret) {
			EMSG("Failed to read MPXY attributes for channel %u",
			     channel_id);
			continue;
		}

		if (channel->attrs.msg_proto_id != SBI_MPXY_MSGPROTO_RPMI_ID) {
			DMSG("Channel %u is not RPMI (proto_id=%u), skipping",
			     channel_id, channel->attrs.msg_proto_id);
			continue;
		}

		ret = sbi_mpxy_rpmi_read_attributes(channel);
		if (ret) {
			EMSG("Failed to read RPMI attributes for channel %u",
			     channel_id);
			continue;
		}

		channel->notif = malloc(mpxy_shmem_size);
		if (!channel->notif) {
			EMSG("No memory for channel %u notif buffer",
			     channel_id);
			goto error;
		}

		memset(channel->notif, 0, mpxy_shmem_size);
		valid_channels++;
	}

	free(channel_ids);
	channel_ids = NULL;

	if (!valid_channels) {
		EMSG("No usable RPMI channels found");
		goto error;
	}

	sbi_mpxy_rpmi_ctx->channel_count = valid_channels;
	return;

error:
	if (channel_ids)
		free(channel_ids);

	if (sbi_mpxy_rpmi_ctx) {
		if (sbi_mpxy_rpmi_ctx->channels) {
			for (i = 0; i < valid_channels; i++)
				free(sbi_mpxy_rpmi_ctx->channels[i].notif);
			free(sbi_mpxy_rpmi_ctx->channels);
		}
		free(sbi_mpxy_rpmi_ctx);
		sbi_mpxy_rpmi_ctx = NULL;
	}
}

/**
 * @brief Reads RPMI-specific attributes from a given MPXY channel.
 *
 * This function queries and fills the RPMI-specific attribute structure
 * (rpmi_attrs) for the specified channel using the SBI MPXY interface.
 *
 * @param channel Pointer to the RPMI channel instance to query.
 *
 * @return 0 on success, or a negative SBI error code on failure.
 */
int sbi_mpxy_rpmi_read_attributes(struct sbi_mpxy_rpmi_channel *channel)
{
	return sbi_mpxy_read_attributes(channel->channel_id,
					SBI_MPXY_ATTR_MSGPROTO_ATTR_START,
					sizeof(channel->rpmi_attrs) /
						sizeof(uint32_t),
					&channel->rpmi_attrs);
}

/**
 * @brief Sends a raw RPMI message over an MPXY channel.
 *
 * This function transmits a message to the associated platform microcontroller
 * (PuC) using the given RPMI-enabled MPXY channel.
 *
 * @param channel Pointer to the RPMI channel used for transmission.
 * @param data Pointer to the message payload to send. It must be a
 *             properly initialized RPMI message structure.
 *
 * @return 0 on success, or a negative RPMI or SBI error code on failure.
 */
int sbi_mpxy_rpmi_send_data(struct sbi_mpxy_rpmi_channel *channel, void *data)
{
	struct sbi_mpxy_rpmi_message *message = data;
	int ret = 0;

	if (channel->attrs.msg_proto_id != SBI_MPXY_MSGPROTO_RPMI_ID)
		return RPMI_ERR_NOTSUPP;

	switch (message->type) {
	case SBI_MPXY_RPMI_MSG_TYPE_GET_ATTRIBUTE:
		switch (message->attribute.id) {
		case SBI_MPXY_RPMI_ATTR_SERVICEGROUP_ID:
			message->attribute.value =
				channel->rpmi_attrs.servicegroup_id;
			break;
		case SBI_MPXY_RPMI_ATTR_SERVICEGROUP_VERSION:
			message->attribute.value =
				channel->rpmi_attrs.servicegroup_version;
			break;
		case SBI_MPXY_RPMI_ATTR_IMPLEMENTATION_ID:
			message->attribute.value =
				channel->rpmi_attrs.implementation_id;
			break;
		case SBI_MPXY_RPMI_ATTR_IMPLEMENTATION_VERSION:
			message->attribute.value =
				channel->rpmi_attrs.implementation_version;
			break;
		default:
			ret = RPMI_ERR_NOTSUPP;
			break;
		}
		break;
	case SBI_MPXY_RPMI_MSG_TYPE_SET_ATTRIBUTE:
		/*
		 * All RPMI Message Protocol Attributes of an SBI MPXY Channel
		 * are RO.
		 */
		ret = RPMI_ERR_NOTSUPP;
		break;
	case SBI_MPXY_RPMI_MSG_TYPE_SEND_WITH_RESPONSE:
		if ((!message->data.request && message->data.request_len) ||
		    (!message->data.response &&
		     message->data.max_response_len)) {
			ret = RPMI_ERR_INVALID_PARAM;
			break;
		}
		if (!(channel->attrs.capability &
		      SBI_MPXY_CHAN_CAP_SEND_WITH_RESP)) {
			ret = RPMI_ERR_IO;
			break;
		}
		ret = sbi_mpxy_send_message_with_response(channel->channel_id
		      , message->data.service_id, message->data.request,
		      message->data.request_len, message->data.response,
		      message->data.max_response_len,
		      &message->data.response_len);
		break;
	case SBI_MPXY_RPMI_MSG_TYPE_SEND_WITHOUT_RESPONSE:
		if (!message->data.request && message->data.request_len) {
			ret = RPMI_ERR_INVALID_PARAM;
			break;
		}
		if (!(channel->attrs.capability &
		      SBI_MPXY_CHAN_CAP_SEND_WITHOUT_RESP)) {
			ret = RPMI_ERR_IO;
			break;
		}
		ret = sbi_mpxy_send_message_without_response(channel->channel_id
		      , message->data.service_id, message->data.request,
		      message->data.request_len);
		break;
	default:
		ret = RPMI_ERR_NOTSUPP;
		break;
	}

	message->error = ret;

	return RPMI_SUCCESS;
}
