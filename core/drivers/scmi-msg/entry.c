// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */
#include <speculation_barrier.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <trace.h>

#include "base.h"
#include "clock.h"
#include "common.h"
#include "reset_domain.h"

void scmi_status_response(struct scmi_msg *msg, int32_t status)
{
	assert(msg->out && msg->out_size >= sizeof(int32_t));

	memcpy(msg->out, &status, sizeof(int32_t));
	msg->out_size_out = sizeof(int32_t);
}

void scmi_write_response(struct scmi_msg *msg, void *payload, size_t size)
{
	/*
	 * Output payload shall be at least the size of the status
	 * Output buffer shall be at least be the size of the status
	 * Output paylaod shall fit in output buffer
	 **/
	assert(payload && size >= sizeof(int32_t) && size <= msg->out_size &&
	       msg->out && msg->out_size >= sizeof(int32_t));

	memcpy(msg->out, payload, size);
	msg->out_size_out = size;
}

scmi_msg_handler_t scmi_get_msg_handler(unsigned int message_id,
					const scmi_msg_handler_t *handler_table,
					size_t elt_count)
{
	const scmi_msg_handler_t *min = handler_table;
	const scmi_msg_handler_t *max = min + elt_count;
	/* Cast discards const qualifier to conform with load_no_speculate_fail() */
	scmi_msg_handler_t *ptr = (scmi_msg_handler_t *)min + message_id;

	return load_no_speculate_fail(ptr, min, max, NULL);
}

void scmi_call_msg_handler(struct scmi_msg *msg,
			   const scmi_msg_handler_t *handler_table,
			   const size_t *payload_size_table,
			   size_t elt_count)
{
	scmi_msg_handler_t handler = scmi_get_msg_handler(msg->message_id,
							  handler_table,
							  elt_count);

	if (!handler) {
		DMSG("Agent %u Protocol %#x Message %#x: not supported",
		     msg->agent_id, msg->protocol_id, msg->message_id);

		scmi_status_response(msg, SCMI_NOT_SUPPORTED);
	} else if (msg->in_size != payload_size_table[msg->message_id]) {
		DMSG("Agent %u Protocol %#x Message %#x: bad payload size",
		     msg->agent_id, msg->protocol_id, msg->message_id);

		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
	} else {
		handler(msg);
	}
}

void scmi_process_message(struct scmi_msg *msg)
{
	switch (msg->protocol_id) {
	case SCMI_PROTOCOL_ID_BASE:
		scmi_call_msg_handler(msg, scmi_base_handler_table,
				      scmi_base_payload_size_table,
				      scmi_base_handler_count);
		return;
#ifdef CFG_SCMI_MSG_CLOCK
	case SCMI_PROTOCOL_ID_CLOCK:
		scmi_call_msg_handler(msg, scmi_clock_handler_table,
				      scmi_clock_payload_size_table,
				      scmi_clock_handler_count);
		return;
#endif
#ifdef CFG_SCMI_MSG_RESET_DOMAIN
	case SCMI_PROTOCOL_ID_RESET_DOMAIN:
		scmi_call_msg_handler(msg, scmi_rd_handler_table,
				      scmi_rd_payload_size_table,
				      scmi_rd_handler_count);
		return;
#endif
	default:
		scmi_status_response(msg, SCMI_NOT_SUPPORTED);
		return;
	}
}
