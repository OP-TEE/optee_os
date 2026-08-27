// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <tmel_com_client.h>
#include <tmel_messages_uids.h>
#include <trace.h>
#include <util.h>

#define TMEL_COM_MBOX_CHANNEL_NAME		"tme-qmp-lite"

/*
 * TME-Lite parses a fixed 24-byte request: a 4-byte header followed by 20
 * bytes of inline payload.
 */
#define TMEL_COM_MBOX_IPC_PACKET_SIZE		24u

/*
 * The SRAM buffer holds TME-Lite's largest message: 14 parameters of at most 3
 * words each (buf, buf_len, buf_len_used).
 */
#define TMEL_COM_SRAM_IPC_MAX_PARAMS		(14u * 3u)

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
	int8_t  response;
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

/*
 * The carveout just above TZDRAM (CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE) holds two
 * cache-coherent buffers shared with TME-Lite: the SRAM IPC buffer, then the
 * client buffer.
 */
#define TMEL_COM_SRAM_BUF_ADDR	TMEL_COM_IPC_BUF_ADDR
#define TMEL_COM_CLIENT_BUF_ADDR	\
	(TMEL_COM_SRAM_BUF_ADDR + TMEL_COM_SRAM_IPC_MAX_BUF_SIZE)
#define TMEL_COM_CLIENT_BUF_SIZE	\
	(CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE - TMEL_COM_SRAM_IPC_MAX_BUF_SIZE)
_Static_assert(CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE >
	       TMEL_COM_SRAM_IPC_MAX_BUF_SIZE,
	       "TMEL-COM carveout size must exceed SRAM IPC buffer size");
_Static_assert(TMEL_COM_CLIENT_BUF_SIZE >= 0x1000,
	       "Client buffer size must be at least 4KB");

/* TME-Lite is given the buffer addresses as 32-bit values. */
_Static_assert(TMEL_COM_SRAM_BUF_ADDR +
	       CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE - 1 <= UINT32_MAX,
	       "TMEL-COM carveout must lie within 32-bit space");

_Static_assert(sizeof(struct tmel_com_mbox_ipc_pkt) ==
	       TMEL_COM_MBOX_IPC_PACKET_SIZE,
	       "IPC packet must be the 24-byte TME-Lite wire format");
_Static_assert(TMEL_COM_MBOX_IPC_PACKET_SIZE <= TME_QMP_LITE_MBOX_SIZE,
	       "IPC packet must fit the mailbox");

register_phys_mem(MEM_AREA_TEE_COHERENT, TMEL_COM_IPC_BUF_ADDR,
		  CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE);

static struct io_pa_va sram_buf;
static struct io_pa_va client_buf;

/*
 * Serialises the session, the mailbox packet and both shared buffers. Held
 * from tmel_com_client_get_coherent_buf() to tmel_com_client_release_buf(), and
 * again, recursively, by each tmel_com_client_send_message() in between.
 */
static struct recursive_mutex tmel_com_mutex = RECURSIVE_MUTEX_INITIALIZER;

static struct tmel_com_ctx tmel_com_ctx;
static struct tmel_com_mbox_ipc_pkt ipc_mailbox;

/* As large as the mailbox, so qcom_mbox_recv() cannot run out of room */
static uint8_t ipc_rx_buf[TME_QMP_LITE_MBOX_SIZE];

void *tmel_com_client_get_coherent_buf(size_t size, paddr_t *phys_addr)
{
	if (!size || size > TMEL_COM_CLIENT_BUF_SIZE)
		return NULL;

	mutex_lock_recursive(&tmel_com_mutex);

	if (!client_buf.va) {
		mutex_unlock_recursive(&tmel_com_mutex);
		return NULL;
	}

	if (phys_addr)
		*phys_addr = client_buf.pa;

	return (void *)client_buf.va;
}

void tmel_com_client_release_buf(void)
{
	/* Scrub before unlocking, so the next owner never sees the contents */
	memset((void *)client_buf.va, 0, TMEL_COM_CLIENT_BUF_SIZE);

	mutex_unlock_recursive(&tmel_com_mutex);
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
 * A request carries no sequence number, so a reply that arrives after its
 * request timed out cannot be told from the next reply. Discard whatever is
 * waiting before sending.
 */
static TEE_Result tmel_com_drop_stale_response(void)
{
	size_t len = sizeof(ipc_rx_buf);
	uint32_t events = 0;

	if (qcom_mbox_process(tmel_com_ctx.chan, &events))
		return TEE_ERROR_COMMUNICATION;

	tmel_com_update_connected(events);

	if (events & QCOM_MBOX_EVT_ERROR)
		return TEE_ERROR_COMMUNICATION;

	if (!(events & QCOM_MBOX_EVT_RX_READY))
		return TEE_SUCCESS;

	if (qcom_mbox_recv(tmel_com_ctx.chan, ipc_rx_buf, &len))
		return TEE_ERROR_COMMUNICATION;

	DMSG("Dropped a stale %zu byte response", len);

	return TEE_SUCCESS;
}

/* Called after QCOM_MBOX_EVT_RX_READY. */
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
		paddr_t pa = (paddr_t)rsp->sram_payload.payload_ptr;
		void *sram_rsp = phys_to_virt(pa, MEM_AREA_TEE_COHERENT,
					      TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);

		if (!sram_rsp) {
			EMSG("Failed to map SRAM response payload");
			return TEE_ERROR_COMMUNICATION;
		}

		memcpy(payload, sram_rsp,
		       MIN(payload_len, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE));
	}

	if (msg_hdr->response) {
		DMSG("Response from TME: %d", msg_hdr->response);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result tmel_com_client_session_start(void)
{
	TEE_Result res = TEE_SUCCESS;
	size_t mtu = 0;

	mutex_lock_recursive(&tmel_com_mutex);

	if (!tmel_com_ctx.chan) {
		res = qcom_mbox_request(TMEL_COM_MBOX_CHANNEL_NAME,
					&tmel_com_ctx.chan);
		if (res) {
			EMSG("Failed to request mailbox channel \"%s\"",
			     TMEL_COM_MBOX_CHANNEL_NAME);
			goto out_unlock;
		}
	}

	res = tmel_com_mbox_wait(QCOM_MBOX_EVT_CONNECTED,
				 TMEL_COM_IPC_MAX_WAIT_FOR_RESPONSE);
	if (res) {
		EMSG("Mailbox did not connect to TME-Lite");
		goto out_unlock;
	}

	/*
	 * The MTU is only valid once connected. Refuse to run rather than
	 * silently truncating requests if the mailbox is smaller than the
	 * packet TME-Lite expects.
	 */
	if (qcom_mbox_get_mtu(tmel_com_ctx.chan, &mtu) ||
	    mtu < sizeof(struct tmel_com_mbox_ipc_pkt)) {
		EMSG("Mailbox MTU %zu too small for a %zu byte IPC packet",
		     mtu, sizeof(struct tmel_com_mbox_ipc_pkt));
		res = TEE_ERROR_COMMUNICATION;
		goto out_unlock;
	}

	if (!sram_buf.va) {
		sram_buf.va =
			(vaddr_t)phys_to_virt(TMEL_COM_SRAM_BUF_ADDR,
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
		client_buf.va =
			(vaddr_t)phys_to_virt(TMEL_COM_CLIENT_BUF_ADDR,
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
		qcom_mbox_release(tmel_com_ctx.chan);
		memset(&tmel_com_ctx, 0, sizeof(tmel_com_ctx));
	}

	mutex_unlock_recursive(&tmel_com_mutex);

	return res;
}

TEE_Result tmel_com_client_send_message(uint32_t tme_msg_uid, uint32_t timeout,
					void *payload, uint32_t payload_len)
{
	union tmel_com_mbox_ipc_payload *ipc_payload = &ipc_mailbox.payload;
	struct tmel_com_ipc_header *msg_hdr = &ipc_mailbox.msg_hdr;
	uint32_t hdr_len = sizeof(struct tmel_com_ipc_header);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!payload || !payload_len ||
	    payload_len > TMEL_COM_SRAM_IPC_MAX_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock_recursive(&tmel_com_mutex);

	if (!tmel_com_ctx.chan) {
		DMSG("No session: msg uid=0x%x", tme_msg_uid);
		goto out;
	}

	res = tmel_com_drop_stale_response();
	if (res)
		goto out;

	if (!tmel_com_ctx.connected) {
		DMSG("Server not connected: msg uid=0x%x", tme_msg_uid);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(&ipc_mailbox, 0, sizeof(ipc_mailbox));
	memset((void *)sram_buf.va, 0, TMEL_COM_SRAM_IPC_MAX_BUF_SIZE);

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
		ipc_payload->sram_payload.payload_ptr = (uint32_t)sram_buf.pa;
		memcpy((void *)sram_buf.va, payload, payload_len);
	}

	msg_hdr->msg_type = TME_MSG_UID_MSG_TYPE(tme_msg_uid);
	msg_hdr->action_id = TME_MSG_UID_ACTION_ID(tme_msg_uid);

	if (qcom_mbox_send(tmel_com_ctx.chan, &ipc_mailbox,
			   sizeof(ipc_mailbox))) {
		EMSG("Mailbox send failed: msg uid=0x%x", tme_msg_uid);
		res = TEE_ERROR_COMMUNICATION;
		goto out;
	}

	res = tmel_com_mbox_wait(QCOM_MBOX_EVT_TX_DONE,
				 TMEL_COM_IPC_MAX_WAIT_FOR_RESPONSE);
	if (res) {
		EMSG("TME-Lite did not consume the request");
		goto out;
	}

	res = tmel_com_mbox_wait(QCOM_MBOX_EVT_RX_READY, timeout);
	if (res) {
		EMSG("No response from TME-Lite");
		goto out;
	}

	res = tmel_com_receive_response(payload, payload_len);
out:
	mutex_unlock_recursive(&tmel_com_mutex);

	return res;
}

early_init(tmel_com_client_session_start);
