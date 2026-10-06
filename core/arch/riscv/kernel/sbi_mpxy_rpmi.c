// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 NXP
 */

#include <riscv.h>
#include <sbi.h>
#include <sbi_mpxy.h>
#include <stdlib.h>
#include <string.h>

#include "sbi_mpxy_rpmi_private.h"

struct sbi_mpxy_rpmi_context *sbi_mpxy_rpmi_ctx;

static int sbi_mpxy_rpmi_read_attributes(struct sbi_mpxy_rpmi_channel *channel);

/**
 * @brief Probes available MPXY channels supporting the RPMI protocol.
 *
 * This function initializes the global RPMI context by identifying available
 * MPXY channels with the RPMI protocol, reading their attributes, and
 * allocating memory for handling notifications. The result is stored in a
 * global context (sbi_mpxy_rpmi_ctx) only after discovery succeeds. Must be
 * called by the primary hart before secondary harts use the channel table.
 *
 * @return TEE_SUCCESS if initialized, otherwise a discovery error.
 */
TEE_Result sbi_mpxy_rpmi_probe_channels(void)
{
	struct sbi_mpxy_rpmi_context *ctx = NULL;
	struct sbi_mpxy_rpmi_channel *channel = NULL;
	uint32_t *channel_ids = NULL;
	unsigned long mpxy_shmem_size = 0;
	uint32_t valid_channels = 0;
	uint32_t i = 0;
	int ret = 0;
	uint32_t channel_id = 0;
	TEE_Result res = TEE_ERROR_COMMUNICATION;

	if (sbi_mpxy_rpmi_ctx)
		return TEE_SUCCESS;

	ret = sbi_mpxy_get_shmem_size(&mpxy_shmem_size);
	if (ret) {
		EMSG("Failed to get MPXY shared memory size (ret=%d)", ret);
		res = sbi_mpxy_to_tee_result(ret);
		goto error;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		EMSG("Out of memory for RPMI context");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	ret = sbi_mpxy_get_channel_count(&ctx->channel_count);
	if (ret || !ctx->channel_count) {
		EMSG("Failed to get MPXY channel count (ret=%d)", ret);
		if (ret)
			res = sbi_mpxy_to_tee_result(ret);
		else
			res = TEE_ERROR_ITEM_NOT_FOUND;
		goto error;
	}

	channel_ids = calloc(ctx->channel_count, sizeof(*channel_ids));
	if (!channel_ids) {
		EMSG("Failed to allocate channel ID list");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	ret = sbi_mpxy_get_channel_ids(ctx->channel_count, channel_ids);
	if (ret) {
		EMSG("Failed to fetch channel IDs (ret=%d)", ret);
		res = sbi_mpxy_to_tee_result(ret);
		goto error;
	}

	ctx->channels = calloc(ctx->channel_count, sizeof(*ctx->channels));
	if (!ctx->channels) {
		EMSG("Failed to allocate channel table");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	for (i = 0; i < ctx->channel_count; i++) {
		channel_id = channel_ids[i];
		channel = &ctx->channels[valid_channels];
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
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto error;
		}

		memset(channel->notif, 0, mpxy_shmem_size);
		/* Respect both scratch-buffer and firmware channel limits. */
		channel->max_xfer_len = MIN(mpxy_shmem_size,
					    channel->attrs.msg_max_len);
		valid_channels++;
	}

	free(channel_ids);
	channel_ids = NULL;

	if (!valid_channels) {
		EMSG("No usable RPMI channels found");
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto error;
	}

	ctx->channel_count = valid_channels;
	sbi_mpxy_rpmi_ctx = ctx;
	return TEE_SUCCESS;

error:
	free(channel_ids);

	if (ctx) {
		if (ctx->channels) {
			for (i = 0; i < valid_channels; i++)
				free(ctx->channels[i].notif);
			free(ctx->channels);
		}
		free(ctx);
	}
	return res;
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
static int sbi_mpxy_rpmi_read_attributes(struct sbi_mpxy_rpmi_channel *channel)
{
	return sbi_mpxy_read_attributes(channel->channel_id,
					SBI_MPXY_ATTR_MSGPROTO_ATTR_START,
					sizeof(channel->rpmi_attrs) /
						sizeof(uint32_t),
					&channel->rpmi_attrs);
}
