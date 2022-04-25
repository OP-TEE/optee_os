// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019-2022, Linaro Limited
 */
#include <assert.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <kernel/spinlock.h>
#include <string.h>
#include <trace.h>

#include "base.h"
#include "clock.h"
#include "common.h"
#include "reset_domain.h"
#include "voltage_domain.h"

/* SMP protection on channel->busy field */
static unsigned int smt_channels_lock;

/* If channel is not busy, set busy and return true, otherwise return false */
bool scmi_msg_claim_channel(struct scmi_msg_channel *channel)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&smt_channels_lock);
	bool channel_is_busy = channel->busy;

	if (!channel_is_busy)
		channel->busy = true;

	cpu_spin_unlock_xrestore(&smt_channels_lock, exceptions);

	return !channel_is_busy;
}

void scmi_msg_release_channel(struct scmi_msg_channel *channel)
{
	channel->busy = false;
}

void scmi_status_response(struct scmi_msg *msg, int32_t status)
{
	assert(msg->out && msg->out_size >= sizeof(int32_t));

	memcpy(msg->out, &status, sizeof(int32_t));
	msg->out_size_out = sizeof(int32_t);
}

void scmi_write_response(struct scmi_msg *msg, void *payload, size_t size)
{
	if (msg->out_size < size) {
		DMSG("SCMI resp. payload %zu > %zu bytes", size, msg->out_size);
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
	} else {
		memcpy(msg->out, payload, size);
		msg->out_size_out = size;
	}
}

void scmi_process_message(struct scmi_msg *msg)
{
	scmi_msg_handler_t handler = NULL;

	switch (msg->protocol_id) {
	case SCMI_PROTOCOL_ID_BASE:
		handler = scmi_msg_get_base_handler(msg);
		break;
	case SCMI_PROTOCOL_ID_CLOCK:
		handler = scmi_msg_get_clock_handler(msg);
		break;
	case SCMI_PROTOCOL_ID_RESET_DOMAIN:
		handler = scmi_msg_get_rd_handler(msg);
		break;
	case SCMI_PROTOCOL_ID_VOLTAGE_DOMAIN:
		handler = scmi_msg_get_voltd_handler(msg);
		break;
	default:
		break;
	}

	if (handler) {
		handler(msg);
		return;
	}

	DMSG("Channel %u Protocol %#x Message %#x: not supported",
	     msg->channel_id, msg->protocol_id, msg->message_id);

	scmi_status_response(msg, SCMI_NOT_SUPPORTED);
}
