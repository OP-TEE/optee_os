// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019-2022, Linaro Limited
 */
#include <assert.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <string.h>
#include <trace.h>

#include "base.h"
#include "clock.h"
#include "common.h"
#include "reset_domain.h"
#include "voltage_domain.h"

/* Provision input message payload buffers for each supported entry channel */
#define SCMI_PAYLOAD_U32_MAX	(SCMI_SEC_PAYLOAD_SIZE / sizeof(uint32_t))

static uint32_t threaded_payload[CFG_NUM_THREADS][SCMI_PAYLOAD_U32_MAX]
__maybe_unused;

static uint32_t interrupt_payload[CFG_TEE_CORE_NB_CORE][SCMI_PAYLOAD_U32_MAX]
__maybe_unused;

static uint32_t fastcall_payload[CFG_TEE_CORE_NB_CORE][SCMI_PAYLOAD_U32_MAX]
__maybe_unused;

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

#ifdef CFG_SCMI_MSG_SMT_FASTCALL_ENTRY
void scmi_smt_fastcall_smc_entry(unsigned int channel_id)
{
	assert(!plat_scmi_get_channel(channel_id)->threaded);

	scmi_entry_smt(channel_id, fastcall_payload[get_core_pos()]);
}
#endif

#ifdef CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY
void scmi_smt_interrupt_entry(unsigned int channel_id)
{
	assert(!plat_scmi_get_channel(channel_id)->threaded);

	scmi_entry_smt(channel_id, interrupt_payload[get_core_pos()]);
}
#endif

#ifdef CFG_SCMI_MSG_SMT_THREAD_ENTRY
void scmi_smt_threaded_entry(unsigned int channel_id)
{
	assert(plat_scmi_get_channel(channel_id)->threaded);

	scmi_entry_smt(channel_id, threaded_payload[thread_get_id()]);
}
#endif

#ifdef CFG_SCMI_MSG_SHM_MSG
TEE_Result scmi_msg_threaded_entry(unsigned int channel_id,
				   void *in_buf, size_t in_size,
				   void *out_buf, size_t *out_size)
{
	assert(plat_scmi_get_channel(channel_id)->threaded);

	return scmi_entry_msg(channel_id, in_buf, in_size, out_buf, out_size,
			      threaded_payload[thread_get_id()]);
}
#endif
