// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <drivers/qcom/mbox/qcom_mbox.h>
#include <initcall.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
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

#define TMEL_COM_IPC_MAX_WAIT_FOR_RESPONSE	TMEL_COM_DEFAULT_TIMEOUT

enum tmel_com_ipc {
	TMEL_COM_IPC_TYPE_MBOX_ONLY = 0,
	TMEL_COM_IPC_TYPE_MBOX_SRAM = 1,
};

struct tmel_com_ipc_header {
	uint8_t ipc_type : 1;
	uint8_t msg_len : 7;
	uint8_t msg_type;
	uint8_t action_id;
	int8_t response;
} __packed;

struct tmel_com_mbox_only_payload {
	uint32_t param[5];
} __packed;

struct tmel_com_sram_payload {
	uint32_t payload_ptr;
	uint32_t payload_len;
} __packed;

union tmel_com_mbox_ipc_payload {
	struct tmel_com_mbox_only_payload mailbox_payload;
	struct tmel_com_sram_payload sram_payload;
} __packed;

struct tmel_com_mbox_ipc_pkt {
	struct tmel_com_ipc_header msg_hdr;
	union tmel_com_mbox_ipc_payload payload;
} __packed;

struct tmel_com_ctx {
	struct qcom_mbox_chan *chan;
	bool connected;
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

register_phys_mem(MEM_AREA_TEE_COHERENT, TMEL_COM_IPC_BUF_ADDR,
		  CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE);

struct tmel_com_buf {
	paddr_t pa;
	void *va;
};

static struct tmel_com_buf sram_buf;
static struct tmel_com_buf client_buf;

/* Serialises the session, the mailbox packet and both shared buffers */
static struct mutex tmel_com_mutex = MUTEX_INITIALIZER;

static struct tmel_com_ctx tmel_com_ctx;
static struct tmel_com_mbox_ipc_pkt ipc_mailbox;

/* ipc_rx_buf is as large as the mailbox, so qcom_mbox_recv() has room */
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

static void tmel_com_update_connected(uint32_t events)
{
	if (events & QCOM_MBOX_EVT_CONNECTED)
		tmel_com_ctx.connected = true;
	else if (events & (QCOM_MBOX_EVT_DISCONNECTED |
			   QCOM_MBOX_EVT_REMOTE_RESET))
		tmel_com_ctx.connected = false;
}

/*
 * tmel_com_mbox_wait() - Poll the mailbox until a wanted event is raised
 *
 * The mailbox framework never waits itself, so every wait in this driver goes
 * through here.
 */
static TEE_Result tmel_com_mbox_wait(uint32_t wanted, uint32_t timeout_us)
{
	uint64_t t = timeout_init_us(timeout_us);
	uint32_t seen = 0;

	while (true) {
		uint32_t events = 0;

		if (qcom_mbox_process(tmel_com_ctx.chan, &events))
			return TEE_ERROR_COMMUNICATION;

		seen |= events;
		tmel_com_update_connected(seen);

		/*
		 * ERROR is sticky and unrecoverable: the channel has to be
		 * released before it can be used again.
		 */
		if (seen & QCOM_MBOX_EVT_ERROR) {
			EMSG("Mailbox reported an unrecoverable error");
			return TEE_ERROR_COMMUNICATION;
		}

		if (seen & wanted)
			return TEE_SUCCESS;

		if (timeout_elapsed(t))
			return TEE_ERROR_TIMEOUT;
	}
}

/*
 * tmel_com_refresh_state() - Pick up mailbox link changes
 *
 * Nothing polls the mailbox between requests, so each request starts here.
 */
static TEE_Result tmel_com_refresh_state(void)
{
	uint32_t events = 0;

	if (qcom_mbox_process(tmel_com_ctx.chan, &events))
		return TEE_ERROR_COMMUNICATION;

	tmel_com_update_connected(events);

	if (events & QCOM_MBOX_EVT_ERROR)
		return TEE_ERROR_COMMUNICATION;

	return TEE_SUCCESS;
}

/*
 * tmel_com_receive_response() - Copy the reply into @payload
 *
 * Call it after QCOM_MBOX_EVT_RX_READY.
 */
static TEE_Result tmel_com_receive_response(void *payload,
					    uint32_t payload_len)
{
	union tmel_com_mbox_ipc_payload *rsp = &ipc_mailbox.payload;
	struct tmel_com_ipc_header *msg_hdr = &ipc_mailbox.msg_hdr;
	size_t len = sizeof(ipc_rx_buf);

	memset(ipc_rx_buf, 0, sizeof(ipc_rx_buf));
	memset(&ipc_mailbox, 0, sizeof(ipc_mailbox));

	if (qcom_mbox_recv(tmel_com_ctx.chan, ipc_rx_buf, &len)) {
		EMSG("Mailbox receive failed");
		return TEE_ERROR_COMMUNICATION;
	}

	if (len < sizeof(struct tmel_com_ipc_header)) {
		EMSG("Response too short: %zu bytes", len);
		return TEE_ERROR_COMMUNICATION;
	}

	memcpy(&ipc_mailbox, ipc_rx_buf,
	       MIN(len, sizeof(struct tmel_com_mbox_ipc_pkt)));

	if (msg_hdr->ipc_type == TMEL_COM_IPC_TYPE_MBOX_ONLY) {
		memcpy(payload, &rsp->mailbox_payload.param,
		       MIN(payload_len,
			   sizeof(struct tmel_com_mbox_only_payload)));
	} else {
		/* The reply is in our SRAM buffer, not where TME-Lite points */
		memcpy(payload, sram_buf.va,
		       MIN(payload_len, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE));
	}

	if (msg_hdr->response) {
		DMSG("Response from TME: %d", msg_hdr->response);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result tmel_com_client_session_start(void)
{
	TEE_Result res = TEE_SUCCESS;
	size_t mtu = 0;

	mutex_lock(&tmel_com_mutex);

	if (!tmel_com_ctx.chan) {
		res = qcom_mbox_request(TME_QMP_LITE_CHANNEL_NAME,
					&tmel_com_ctx.chan);
		if (res) {
			EMSG("Failed to request mailbox channel \"%s\"",
			     TME_QMP_LITE_CHANNEL_NAME);
			goto out_unlock;
		}
	}

	res = tmel_com_mbox_wait(QCOM_MBOX_EVT_CONNECTED,
				 TMEL_COM_IPC_MAX_WAIT_FOR_RESPONSE);
	if (res) {
		EMSG("Mailbox did not connect to TME-Lite");
		goto out_unlock;
	}

	/* The MTU is only valid once connected */
	if (qcom_mbox_get_mtu(tmel_com_ctx.chan, &mtu) ||
	    mtu < sizeof(struct tmel_com_mbox_ipc_pkt)) {
		EMSG("Mailbox MTU %zu too small for a %zu byte IPC packet",
		     mtu, sizeof(struct tmel_com_mbox_ipc_pkt));
		res = TEE_ERROR_COMMUNICATION;
		goto out_unlock;
	}

	if (!sram_buf.va) {
		sram_buf.va = phys_to_virt(TMEL_COM_SRAM_BUF_ADDR,
					   MEM_AREA_TEE_COHERENT,
					   TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);
		if (!sram_buf.va) {
			EMSG("Failed to get SRAM coherent VA");
			res = TEE_ERROR_GENERIC;
			goto out_unlock;
		}
		sram_buf.pa = TMEL_COM_SRAM_BUF_ADDR;
	}

	if (!client_buf.va) {
		client_buf.va = phys_to_virt(TMEL_COM_CLIENT_BUF_ADDR,
					     MEM_AREA_TEE_COHERENT,
					     TMEL_COM_CLIENT_BUF_SIZE);
		if (!client_buf.va) {
			EMSG("Failed to get client coherent VA");
			res = TEE_ERROR_GENERIC;
			goto out_unlock;
		}
		client_buf.pa = TMEL_COM_CLIENT_BUF_ADDR;
	}

out_unlock:
	if (res) {
		qcom_mbox_release(&tmel_com_ctx.chan);
		memset(&tmel_com_ctx, 0, sizeof(tmel_com_ctx));
	}

	mutex_unlock(&tmel_com_mutex);

	return res;
}

TEE_Result tmel_com_client_send_message(uint32_t tme_msg_uid, uint32_t timeout,
					void *payload, uint32_t payload_len,
					const struct tmel_com_data *data)
{
	union tmel_com_mbox_ipc_payload *ipc_payload = &ipc_mailbox.payload;
	struct tmel_com_ipc_header *msg_hdr = &ipc_mailbox.msg_hdr;
	uint32_t hdr_len = sizeof(struct tmel_com_ipc_header);
	size_t in_len = data ? data->in_len : 0;
	size_t out_len = data ? data->out_len : 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!payload || !payload_len ||
	    payload_len > TMEL_COM_SRAM_IPC_MAX_BUF_SIZE ||
	    MAX(in_len, out_len) > TMEL_COM_CLIENT_BUF_SIZE ||
	    (in_len && !data->in) || (out_len && !data->out))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&tmel_com_mutex);

	if (!tmel_com_ctx.chan) {
		EMSG("No session: msg uid=0x%x", tme_msg_uid);
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	res = tmel_com_refresh_state();
	if (res)
		goto out;

	if (!tmel_com_ctx.connected) {
		EMSG("Server not connected: msg uid=0x%x", tme_msg_uid);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(&ipc_mailbox, 0, sizeof(ipc_mailbox));
	memset(sram_buf.va, 0, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);
	if (in_len)
		memcpy(client_buf.va, data->in, in_len);

	if (payload_len <= TMEL_COM_MBOX_IPC_PACKET_SIZE - hdr_len) {
		msg_hdr->ipc_type = TMEL_COM_IPC_TYPE_MBOX_ONLY;
		msg_hdr->msg_len = payload_len;
		memcpy(&ipc_payload->mailbox_payload.param, payload,
		       MIN(payload_len,
			   sizeof(struct tmel_com_mbox_only_payload)));
	} else {
		msg_hdr->ipc_type = TMEL_COM_IPC_TYPE_MBOX_SRAM;
		msg_hdr->msg_len = sizeof(struct tmel_com_sram_payload);
		ipc_payload->sram_payload.payload_len = payload_len;
		ipc_payload->sram_payload.payload_ptr = sram_buf.pa;
		memcpy(sram_buf.va, payload, payload_len);
	}

	msg_hdr->msg_type = TME_MSG_UID_MSG_TYPE(tme_msg_uid);
	msg_hdr->action_id = TME_MSG_UID_ACTION_ID(tme_msg_uid);

	if (qcom_mbox_send(tmel_com_ctx.chan, &ipc_mailbox,
			   sizeof(ipc_mailbox))) {
		EMSG("Mailbox send failed: msg uid=0x%x", tme_msg_uid);
		res = TEE_ERROR_COMMUNICATION;
		goto out_scrub;
	}

	res = tmel_com_mbox_wait(QCOM_MBOX_EVT_TX_DONE,
				 TMEL_COM_IPC_MAX_WAIT_FOR_RESPONSE);
	if (res) {
		EMSG("TME-Lite did not consume the request");
		goto out_scrub;
	}

	/*
	 * A request has no sequence number, so this relies on TME-Lite
	 * answering, or giving up, before this timeout: a reply must never
	 * arrive after the next request has been sent.
	 */
	res = tmel_com_mbox_wait(QCOM_MBOX_EVT_RX_READY, timeout);
	if (res) {
		EMSG("No response from TME-Lite");
		goto out_scrub;
	}

	res = tmel_com_receive_response(payload, payload_len);
	if (!res && out_len)
		memcpy(data->out, client_buf.va, out_len);

out_scrub:
	memset(client_buf.va, 0, MAX(in_len, out_len));
out:
	mutex_unlock(&tmel_com_mutex);

	return res;
}

early_init_late(tmel_com_client_session_start);
