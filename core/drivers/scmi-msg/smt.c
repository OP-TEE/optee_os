// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019-2020, Linaro Limited
 */
#include <assert.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <io.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "common.h"

/* Legacy SMT/SCMI messages are 128 bytes at most including SMT header */
#define SCMI_PLAYLOAD_MAX		92
#define SCMI_PLAYLOAD_U32_MAX		(SCMI_PLAYLOAD_MAX / sizeof(uint32_t))

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

/* SMP protection on channel access */
static unsigned int smt_channels_lock;

/* If channel is not busy, set busy and return true, otherwise return false */
static bool channel_set_busy(struct scmi_msg_channel *chan)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&smt_channels_lock);
	bool channel_is_busy = chan->busy;

	if (!channel_is_busy)
		chan->busy = true;

	cpu_spin_unlock_xrestore(&smt_channels_lock, exceptions);

	return !channel_is_busy;
}

static void channel_release_busy(struct scmi_msg_channel *chan)
{
	chan->busy = false;
}

static struct smt_header *channel_to_smt_hdr(struct scmi_msg_channel *chan)
{
	return (struct smt_header *)io_pa_or_va(&chan->shm_addr,
						sizeof(struct smt_header));
}

/*
 * Creates a SCMI message instance in secure memory and push it in the SCMI
 * message drivers. Message structure contains SCMI protocol meta-data and
 * references to input payload in secure memory and output message buffer
 * in shared memory.
 */
static void scmi_process_smt(unsigned int channel_id, uint32_t *payload_buf)
{
	struct scmi_msg_channel *chan = NULL;
	struct smt_header *smt_hdr = NULL;
	size_t in_payload_size = 0;
	uint32_t smt_status = 0;
	struct scmi_msg msg = { };
	bool error = true;

	chan = plat_scmi_get_channel(channel_id);
	if (!chan)
		return;

	smt_hdr = channel_to_smt_hdr(chan);
	assert(smt_hdr);

	smt_status = READ_ONCE(smt_hdr->status);

	if (!channel_set_busy(chan)) {
		DMSG("SCMI channel %u busy", channel_id);
		goto out;
	}

	in_payload_size = READ_ONCE(smt_hdr->length) -
			  sizeof(smt_hdr->message_header);

	if (in_payload_size > SCMI_PLAYLOAD_MAX) {
		DMSG("SCMI payload too big %u", in_payload_size);
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
	msg.out_size = chan->shm_size - sizeof(*smt_hdr);

	assert(msg.out && msg.out_size >= sizeof(int32_t));

	/* Here the payload is copied in secure memory */
	memcpy(msg.in, smt_hdr->payload, in_payload_size);

	msg.protocol_id = SMT_HDR_PROT_ID(smt_hdr->message_header);
	msg.message_id = SMT_HDR_MSG_ID(smt_hdr->message_header);
	msg.channel_id = channel_id;

	scmi_process_message(&msg);

	/* Update message length with the length of the response message */
	smt_hdr->length = msg.out_size_out + sizeof(smt_hdr->message_header);

	channel_release_busy(chan);
	error = false;

out:
	if (error) {
		DMSG("SCMI error");
		smt_hdr->status |= SMT_STATUS_ERROR | SMT_STATUS_FREE;
	} else {
		smt_hdr->status |= SMT_STATUS_FREE;
	}
}

#ifdef CFG_SCMI_MSG_SMT_FASTCALL_ENTRY
/* Provision input message payload buffers for fastcall SMC context entries */
static uint32_t fast_smc_payload[CFG_TEE_CORE_NB_CORE][SCMI_PLAYLOAD_U32_MAX];

void scmi_smt_fastcall_smc_entry(unsigned int channel_id)
{
	scmi_process_smt(channel_id, fast_smc_payload[get_core_pos()]);
}
#endif

#ifdef CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY
/* Provision input message payload buffers for fastcall SMC context entries */
static uint32_t interrupt_payload[CFG_TEE_CORE_NB_CORE][SCMI_PLAYLOAD_U32_MAX];

void scmi_smt_interrupt_entry(unsigned int channel_id)
{
	scmi_process_smt(channel_id, interrupt_payload[get_core_pos()]);
}
#endif

#ifdef CFG_SCMI_MSG_SMT_THREAD_ENTRY
/* Provision input message payload buffers for fastcall SMC context entries */
static uint32_t threaded_payload[CFG_NUM_THREADS][SCMI_PLAYLOAD_U32_MAX];

void scmi_smt_threaded_entry(unsigned int channel_id)
{
	assert(plat_scmi_get_channel(channel_id)->threaded);

	scmi_process_smt(channel_id, threaded_payload[thread_get_id()]);
}
#endif

/* Init a SMT header for a shared memory buffer: state it a free/no-error */
void scmi_smt_init_agent_channel(struct scmi_msg_channel *chan)
{
	COMPILE_TIME_ASSERT(SCMI_PLAYLOAD_MAX + sizeof(struct smt_header) <=
			    SMT_BUF_SLOT_SIZE);

	if (chan) {
		struct smt_header *smt_header = channel_to_smt_hdr(chan);

		if (smt_header) {
			memset(smt_header, 0, sizeof(*smt_header));
			smt_header->status = SMT_STATUS_FREE;

			return;
		}
	}

	panic();
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
