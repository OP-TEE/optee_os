// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019-2022, Linaro Limited
 */
#include <assert.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <io.h>
#include <stdbool.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "common.h"

/**
 * struct smt_header - SMT formatted header for SMT base shared memory transfer
 *
 * @status: Bit flags, see SMT_STATUS_*
 * @flags: Bit flags, see SMT_FLAG_*
 * @length: Byte size of message payload (variable) + ::message_header (32bit)
 * payload: SCMI message payload data
 */
struct smt_header {
	uint32_t reserved0;
	uint32_t status;
	uint64_t reserved1;
	uint32_t flags;
	uint32_t length; /* message_header + payload */
	uint32_t message_header;
	uint32_t payload[];
};

/* Flag set in smt_header::status when SMT does not contain pending message */
#define SMT_STATUS_FREE			BIT(0)
/* Flag set in smt_header::status when SMT reports an error */
#define SMT_STATUS_ERROR		BIT(1)

/* Flag set in smt_header::flags when SMT uses interrupts */
#define SMT_FLAG_INTR_ENABLED		BIT(1)

/* Bit fields packed in smt_header::message_header */
#define SMT_MSG_ID_MASK			GENMASK_32(7, 0)
#define SMT_HDR_MSG_ID(_hdr)		((_hdr) & SMT_MSG_ID_MASK)

#define SMT_MSG_TYPE_MASK		GENMASK_32(9, 8)
#define SMT_HDR_TYPE_ID(_hdr)		(((_hdr) & SMT_MSG_TYPE_MASK) >> 8)

#define SMT_MSG_PROT_ID_MASK		GENMASK_32(17, 10)
#define SMT_HDR_PROT_ID(_hdr)		(((_hdr) & SMT_MSG_PROT_ID_MASK) >> 10)

static struct smt_header *channel_to_smt_hdr(struct scmi_msg_channel *channel)
{
	if (!channel)
		return NULL;

	return (struct smt_header *)io_pa_or_va(&channel->shm_addr,
						sizeof(struct smt_header));
}

/*
 * Creates a SCMI message instance in secure memory and push it in the SCMI
 * message drivers. Message structure contains SCMI protocol meta-data and
 * references to input payload in secure memory and output message buffer
 * in shared memory.
 */
void scmi_entry_smt(unsigned int channel_id, uint32_t *payload_buf)
{
	struct scmi_msg_channel *channel = NULL;
	struct smt_header *smt_hdr = NULL;
	size_t in_payload_size = 0;
	uint32_t smt_status = 0;
	struct scmi_msg msg = { };
	bool error = true;

	channel = plat_scmi_get_channel(channel_id);
	if (!channel) {
		DMSG("Invalid channel ID %u", channel_id);
		return;
	}

	smt_hdr = channel_to_smt_hdr(channel);
	if (!smt_hdr) {
		DMSG("No shared buffer for channel ID %u", channel_id);
		return;
	}

	if (!scmi_msg_claim_channel(channel)) {
		DMSG("SCMI channel %u busy", channel_id);
		goto out;
	}

	smt_status = READ_ONCE(smt_hdr->status);

	in_payload_size = READ_ONCE(smt_hdr->length) -
			  sizeof(smt_hdr->message_header);

	if (in_payload_size > SCMI_SEC_PAYLOAD_SIZE) {
		DMSG("SCMI payload too big %zu", in_payload_size);
		goto out;
	}

	if (smt_status & (SMT_STATUS_ERROR | SMT_STATUS_FREE)) {
		DMSG("SCMI channel bad status 0x%x",
		     smt_hdr->status & (SMT_STATUS_ERROR | SMT_STATUS_FREE));
		goto out;
	}

	/* Fill message */
	msg.in = (char *)payload_buf;
	msg.in_size = in_payload_size;
	msg.out = (char *)smt_hdr->payload;
	msg.out_size = channel->shm_size - sizeof(*smt_hdr);

	assert(msg.out && msg.out_size >= sizeof(int32_t));

	/* Here the payload is copied in secure memory */
	memcpy(msg.in, smt_hdr->payload, in_payload_size);

	msg.protocol_id = SMT_HDR_PROT_ID(smt_hdr->message_header);
	msg.message_id = SMT_HDR_MSG_ID(smt_hdr->message_header);
	msg.channel_id = channel_id;

	scmi_process_message(&msg);

	/* Update message length with the length of the response message */
	smt_hdr->length = msg.out_size_out + sizeof(smt_hdr->message_header);

	scmi_msg_release_channel(channel);
	error = false;

out:
	if (error) {
		DMSG("SCMI error");
		smt_hdr->status |= SMT_STATUS_ERROR | SMT_STATUS_FREE;
	} else {
		smt_hdr->status |= SMT_STATUS_FREE;
	}
}

/* Init a SMT header for a shared memory buffer: state it a free/no-error */
void scmi_smt_init_agent_channel(struct scmi_msg_channel *channel)
{
	struct smt_header *smt_header = channel_to_smt_hdr(channel);

	static_assert(SCMI_SEC_PAYLOAD_SIZE + sizeof(struct smt_header) <=
		      SMT_BUF_SLOT_SIZE &&
		      IS_ALIGNED(SCMI_SEC_PAYLOAD_SIZE, sizeof(uint32_t)));
	assert(smt_header);

	memset(smt_header, 0, sizeof(*smt_header));
	smt_header->status = SMT_STATUS_FREE;
}

void scmi_smt_set_shared_buffer(struct scmi_msg_channel *channel, void *base)
{
	paddr_t p_base = 0;

	if (base) {
		assert(!channel->shm_addr.va && !channel->shm_addr.pa);
		p_base = virt_to_phys(base);
		assert(p_base);
	}

	channel->shm_addr.va = (vaddr_t)base;
	channel->shm_addr.pa = p_base;
}
