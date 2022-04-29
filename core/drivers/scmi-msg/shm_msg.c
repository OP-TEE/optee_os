// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, Linaro Limited
 */
#include <assert.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <io.h>
#include <kernel/misc.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "common.h"

/**
 * struct msg_header - MSG formatted header for MSG base shared memory transfer
 *
 * @message_header: 32bit header used in MSG shared memory protocol
 * @payload: SCMI message payload data
 */
struct msg_header {
	uint32_t message_header;
	uint32_t payload[];
};

/* Bit fields packed in msg_header::message_header */
#define MSG_ID_MASK		GENMASK_32(7, 0)
#define MSG_ID(_hdr)		((_hdr) & MSG_ID_MASK)

#define MSG_TYPE_MASK		GENMASK_32(9, 8)
#define MSG_TYPE(_hdr)		(((_hdr) & MSG_TYPE_MASK) >> 8)

#define MSG_PROT_ID_MASK	GENMASK_32(17, 10)
#define MSG_PROT_ID(_hdr)	(((_hdr) & MSG_PROT_ID_MASK) >> 10)

/*
 * Creates a SCMI message instance in secure memory and push it in the SCMI
 * message drivers. Message structure contains SCMI protocol meta-data and
 * references to input payload in secure memory and output message buffer
 * in shared memory.
 */
TEE_Result scmi_entry_msg(unsigned int channel_id, void *in_buf, size_t in_size,
			  void *out_buf, size_t *out_size, uint32_t *sec_buf)
{
	struct scmi_msg_channel *channel = plat_scmi_get_channel(channel_id);
	struct msg_header *hdr = NULL;
	struct scmi_msg msg = { };
	uint32_t msg_header = 0;

	if (!channel) {
		DMSG("Invalid channel ID %u", channel_id);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	assert(in_buf && out_buf && out_size && sec_buf);

	if (in_size < sizeof(struct msg_header) ||
	    in_size - sizeof(struct msg_header) > SCMI_SEC_PAYLOAD_SIZE ||
	    !IS_ALIGNED_WITH_TYPE(in_buf, uint32_t) ||
	    *out_size < sizeof(struct msg_header) ||
	    !IS_ALIGNED_WITH_TYPE(out_buf, uint32_t)) {
		DMSG("Invalid SCMI buffer references %zu@%p / %zu@%p",
		     in_size, in_buf, *out_size, out_buf);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!scmi_msg_claim_channel(channel)) {
		DMSG("SCMI channel %u busy", channel_id);
		return TEE_ERROR_BUSY;
	}

	/* Copy SCMI protocol data and message payload in secure memory */
	hdr = (struct msg_header *)in_buf;
	msg_header = READ_ONCE(hdr->message_header);

	msg.protocol_id = MSG_PROT_ID(msg_header);
	msg.message_id = MSG_ID(msg_header);
	msg.channel_id = channel_id;

	msg.in = (char *)sec_buf;
	msg.in_size = in_size - sizeof(struct msg_header);
	memcpy(msg.in, hdr->payload, msg.in_size);

	/* Prepare output message buffer references */
	hdr = (struct msg_header *)out_buf;

	msg.out = (char *)hdr->payload;
	msg.out_size = *out_size - sizeof(struct msg_header);

	scmi_process_message(&msg);

	/* Update SCMI protocol data and output shared buffer size */
	hdr->message_header = msg_header;
	*out_size = msg.out_size_out + sizeof(struct msg_header);

	scmi_msg_release_channel(channel);

	return TEE_SUCCESS;
}
