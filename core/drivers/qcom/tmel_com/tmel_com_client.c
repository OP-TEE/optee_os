// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <drivers/mailbox.h>
#include <drivers/qcom/mbox/qcom_mbox.h>
#include <initcall.h>
#include <inttypes.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <string_ext.h>
#include <tmel_com_client.h>
#include <tmel_messages_uids.h>
#include <trace.h>
#include <util.h>

/*
 * Size of the request packet: TME-Lite parses a fixed 24 bytes, a 4-byte header
 * followed by 20 bytes of inline payload.
 */
#define TMEL_COM_MBOX_IPC_PACKET_SIZE		24U

/*
 * Words in the SRAM buffer: it holds TME-Lite's largest message, 14 parameters
 * of at most 3 words each (buf, buf_len, buf_len_used).
 */
#define TMEL_COM_SRAM_IPC_MAX_PARAMS		(14U * 3U)

#define TMEL_COM_SRAM_IPC_MAX_BUF_SIZE		\
	(TMEL_COM_SRAM_IPC_MAX_PARAMS * sizeof(uint32_t))

/*
 * Packet header word. Bit 0 is set when the payload is in the SRAM buffer;
 * TME-Lite writes the response code (0 = success) in the reply.
 */
#define TMEL_COM_HDR_IPC_TYPE_SRAM	BIT32(0)
#define TMEL_COM_HDR_MSG_LEN(x)		(SHIFT_U32(x, 1) & GENMASK_32(7, 1))
#define TMEL_COM_HDR_MSG_TYPE(x)	(SHIFT_U32(x, 8) & GENMASK_32(15, 8))
#define TMEL_COM_HDR_ACTION_ID(x)	(SHIFT_U32(x, 16) & GENMASK_32(23, 16))
#define TMEL_COM_HDR_RESPONSE_SHIFT	24
#define TMEL_COM_HDR_RESPONSE_MASK	GENMASK_32(31, 24)

struct tmel_com_mbox_only_payload {
	uint32_t param[5];
};

struct tmel_com_sram_payload {
	uint32_t payload_ptr;
	uint32_t payload_len;
};

union tmel_com_mbox_ipc_payload {
	struct tmel_com_mbox_only_payload mailbox_payload;
	struct tmel_com_sram_payload sram_payload;
};

struct tmel_com_mbox_ipc_pkt {
	uint32_t hdr;
	union tmel_com_mbox_ipc_payload payload;
};

/* The carveout holds the SRAM IPC buffer, then the client buffer */
#define TMEL_COM_SRAM_BUF_ADDR	TMEL_COM_IPC_BUF_ADDR
#define TMEL_COM_CLIENT_BUF_ADDR	\
	(TMEL_COM_SRAM_BUF_ADDR + TMEL_COM_SRAM_IPC_MAX_BUF_SIZE)
#define TMEL_COM_CLIENT_BUF_SIZE	\
	(CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE - TMEL_COM_SRAM_IPC_MAX_BUF_SIZE)
static_assert(CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE >
	      TMEL_COM_SRAM_IPC_MAX_BUF_SIZE,
	      "TMEL-COM carveout size must exceed SRAM IPC buffer size");
static_assert(TMEL_COM_CLIENT_BUF_SIZE >= 0x1000,
	      "Client buffer size must be at least 4KB");

/* TME-Lite is given the buffer addresses as 32-bit values. */
static_assert(TMEL_COM_SRAM_BUF_ADDR +
	      CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE - 1 <= UINT32_MAX,
	      "TMEL-COM carveout must lie within 32-bit space");

static_assert(sizeof(struct tmel_com_mbox_ipc_pkt) ==
	      TMEL_COM_MBOX_IPC_PACKET_SIZE,
	      "IPC packet must be the 24-byte TME-Lite wire format");
static_assert(TMEL_COM_MBOX_IPC_PACKET_SIZE <= TME_QMP_LITE_MBOX_SIZE,
	      "IPC packet must fit the mailbox");

/* Serialises the mailbox packet and both shared buffers */
static struct mutex tmel_com_mutex = MUTEX_INITIALIZER;

static struct mbox_chan *tmel_com_chan;
static struct tmel_com_mbox_ipc_pkt ipc_mailbox;

/* Looked up at session start, before tmel_com_chan is set */
static void *ipc_sram_buf;
static void *ipc_client_buf;

/* As large as the mailbox, so a reply never gets TEE_ERROR_SHORT_BUFFER */
static uint8_t ipc_rx_buf[TME_QMP_LITE_MBOX_SIZE];

paddr_t tmel_com_client_data_pa(void)
{
	return TMEL_COM_CLIENT_BUF_ADDR;
}

TEE_Result tme_status_to_tee_result(uint32_t tme_status)
{
	switch (tme_status) {
	case TME_STATUS_SUCCESS:
		return TEE_SUCCESS;
	case TME_STATUS_INVALID_INPUT:
		return TEE_ERROR_BAD_PARAMETERS;
	default:
		return TEE_ERROR_GENERIC;
	}
}

/*
 * tmel_com_receive_response() - Wait for the reply and copy it into @payload
 *
 * The mailbox never waits for a reply, so poll it until @timeout_us is up.
 */
static TEE_Result tmel_com_receive_response(void *payload, size_t payload_len,
					    uint32_t timeout_us)
{
	union tmel_com_mbox_ipc_payload *rsp = &ipc_mailbox.payload;
	struct qcom_mbox_msg msg = { .buf = ipc_rx_buf };
	uint64_t t = timeout_init_us(timeout_us);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t response = 0;

	memset(ipc_rx_buf, 0, sizeof(ipc_rx_buf));
	memset(&ipc_mailbox, 0, sizeof(ipc_mailbox));

	do {
		msg.len = sizeof(ipc_rx_buf);
		res = mbox_recv_sync(tmel_com_chan, &msg);
	} while (res == TEE_ERROR_NO_DATA && !timeout_elapsed(t));

	if (res == TEE_ERROR_NO_DATA) {
		EMSG("No response from TME-Lite");
		return TEE_ERROR_TIMEOUT;
	}
	if (res) {
		EMSG("Mailbox receive failed: %#" PRIx32, res);
		return TEE_ERROR_COMMUNICATION;
	}

	if (msg.len < sizeof(ipc_mailbox.hdr)) {
		EMSG("Response too short: %zu bytes", msg.len);
		return TEE_ERROR_COMMUNICATION;
	}

	memcpy(&ipc_mailbox, ipc_rx_buf,
	       MIN(msg.len, sizeof(struct tmel_com_mbox_ipc_pkt)));

	if (ipc_mailbox.hdr & TMEL_COM_HDR_IPC_TYPE_SRAM) {
		/* The reply is in our SRAM buffer, not where TME-Lite points */
		memcpy(payload, ipc_sram_buf,
		       MIN(payload_len, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE));
	} else {
		memcpy(payload, &rsp->mailbox_payload.param,
		       MIN(payload_len,
			   sizeof(struct tmel_com_mbox_only_payload)));
	}

	response = (ipc_mailbox.hdr & TMEL_COM_HDR_RESPONSE_MASK) >>
		   TMEL_COM_HDR_RESPONSE_SHIFT;
	if (response) {
		DMSG("Response from TME: %#" PRIx32, response);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result tmel_com_client_session_start(void)
{
	struct mbox_controller *controller = qcom_mbox_get_controller();
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!controller) {
		EMSG("No TME-Lite mailbox controller");
		return TEE_ERROR_BAD_STATE;
	}

	ipc_sram_buf = phys_to_virt(TMEL_COM_SRAM_BUF_ADDR,
				    MEM_AREA_IO_SEC,
				    TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);
	ipc_client_buf = phys_to_virt(TMEL_COM_CLIENT_BUF_ADDR,
				      MEM_AREA_IO_SEC,
				      TMEL_COM_CLIENT_BUF_SIZE);
	if (!ipc_sram_buf || !ipc_client_buf) {
		EMSG("TME-Lite IPC buffers are not mapped");
		return TEE_ERROR_BAD_STATE;
	}

	/* Waits for the mailbox to connect to TME-Lite */
	res = mbox_request_channel(controller, NULL, 0, &tmel_com_chan);
	if (res)
		EMSG("No TME-Lite mailbox channel: %#" PRIx32, res);

	return res;
}

TEE_Result tmel_com_client_send_message(uint32_t tme_msg_uid, uint32_t timeout,
					void *payload, size_t payload_len,
					const struct tmel_com_data *data)
{
	union tmel_com_mbox_ipc_payload *ipc_payload = &ipc_mailbox.payload;
	size_t hdr_len = sizeof(ipc_mailbox.hdr);
	size_t in_len = data ? data->in_len : 0;
	size_t out_len = data ? data->out_len : 0;
	struct qcom_mbox_msg msg = { .buf = &ipc_mailbox,
				     .len = sizeof(ipc_mailbox) };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!payload || !payload_len ||
	    payload_len > TMEL_COM_SRAM_IPC_MAX_BUF_SIZE ||
	    MAX(in_len, out_len) > TMEL_COM_CLIENT_BUF_SIZE ||
	    (in_len && !data->in) || (out_len && !data->out))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&tmel_com_mutex);

	if (!tmel_com_chan) {
		EMSG("No session: msg uid=%#" PRIx32, tme_msg_uid);
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	memset(&ipc_mailbox, 0, sizeof(ipc_mailbox));
	memset(ipc_sram_buf, 0, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);
	if (in_len)
		memcpy(ipc_client_buf, data->in, in_len);

	if (payload_len <= TMEL_COM_MBOX_IPC_PACKET_SIZE - hdr_len) {
		ipc_mailbox.hdr = TMEL_COM_HDR_MSG_LEN(payload_len);
		memcpy(&ipc_payload->mailbox_payload.param, payload,
		       MIN(payload_len,
			   sizeof(struct tmel_com_mbox_only_payload)));
	} else {
		ipc_mailbox.hdr = TMEL_COM_HDR_IPC_TYPE_SRAM |
			TMEL_COM_HDR_MSG_LEN(sizeof(ipc_payload->sram_payload));
		ipc_payload->sram_payload.payload_len = payload_len;
		ipc_payload->sram_payload.payload_ptr = TMEL_COM_SRAM_BUF_ADDR;
		memcpy(ipc_sram_buf, payload, payload_len);
	}

	ipc_mailbox.hdr |=
		TMEL_COM_HDR_MSG_TYPE(TME_MSG_UID_MSG_TYPE(tme_msg_uid)) |
		TMEL_COM_HDR_ACTION_ID(TME_MSG_UID_ACTION_ID(tme_msg_uid));

	res = mbox_send_sync(tmel_com_chan, &msg);
	if (res == TEE_ERROR_BAD_STATE) {
		EMSG("Server not connected: msg uid=%#" PRIx32, tme_msg_uid);
		res = TEE_ERROR_GENERIC;
		goto out_scrub;
	}
	if (res) {
		EMSG("Mailbox send failed: msg uid=%#" PRIx32 ": %#" PRIx32,
		     tme_msg_uid, res);
		res = TEE_ERROR_COMMUNICATION;
		goto out_scrub;
	}

	/*
	 * A request has no sequence number, so this relies on TME-Lite
	 * answering, or giving up, before this timeout: a reply must never
	 * arrive after the next request has been sent.
	 */
	res = tmel_com_receive_response(payload, payload_len, timeout);
	if (!res && out_len)
		memcpy(data->out, ipc_client_buf, out_len);

out_scrub:
	memzero_explicit(ipc_client_buf, TMEL_COM_CLIENT_BUF_SIZE);
	memzero_explicit(ipc_sram_buf, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);
out:
	mutex_unlock(&tmel_com_mutex);

	return res;
}

early_init_late(tmel_com_client_session_start);
