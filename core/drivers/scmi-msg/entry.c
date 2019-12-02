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

scmi_msg_handler_t scmi_get_msg_handler(unsigned int message_id,
					const scmi_msg_handler_t *handler_table,
					size_t elt_count)
{
	/* Cast discards const qualifier to ease code readibility */
	scmi_msg_handler_t *min = (scmi_msg_handler_t *)handler_table;
	scmi_msg_handler_t *max = min + elt_count;
	scmi_msg_handler_t *ptr = min + message_id;

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
	default:
		scmi_status_response(msg, SCMI_NOT_SUPPORTED);
		return;
	}
}
