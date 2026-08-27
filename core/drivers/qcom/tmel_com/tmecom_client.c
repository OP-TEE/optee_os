// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "tmecom_client.h"
#include "tmemessages_uids.h"

/* Mailbox channel published by the platform channel table. */
#define TMECOM_MBOX_CHANNEL_NAME		"tme-qmp-lite"

/*
 * IPC Packet Definitions
 *
 * TME-Lite parses a fixed 24-byte request: a 4-byte header followed by up to
 * 20 bytes of inline payload.  The 8 bytes subtracted here are the QMP control
 * data.  QMP-Lite keeps its control word in a descriptor register outside the
 * payload area, so the full mailbox width is available, but the 24-byte layout
 * is retained because it is the wire format TME-Lite expects.
 */
#define TMECOM_HW_MBOX_SIZE			32u
#define TMECOM_MBOX_QMP_CONTROL_DATA_SIZE	8u
#define TMECOM_MBOX_IPC_PACKET_SIZE		\
	(TMECOM_HW_MBOX_SIZE - TMECOM_MBOX_QMP_CONTROL_DATA_SIZE)
#define TMECOM_MBOX_IPC_MAX_PARAMS		5u

/*
 * 32bit ParamID consists of paramCount(4b) and paramType(2b) for each params.
 * Max 14 params can be described using 32b paramID.
 */
#define TMECOM_MAX_PARAM_IN_PARAM_ID		14u

/* bufAddr, bufLen, bufOutLen */
#define TMECOM_PARAM_CNT_FOR_PARAM_TYPE_OUTBUF	3u

/*
 * In worst case when all 14 params are of type TME_MSG_PARAM_TYPE_BUF_OUT or
 * TME_MSG_PARAM_TYPE_BUF_IN_OUT, then total params will be 42(14*3)
 */
#define TMECOM_SRAM_IPC_MAX_PARAMS		\
	((TMECOM_MAX_PARAM_IN_PARAM_ID) * \
	 (TMECOM_PARAM_CNT_FOR_PARAM_TYPE_OUTBUF)) /* 14*3 */

#define TMECOM_SRAM_IPC_MAX_BUF_SIZE		\
	(TMECOM_SRAM_IPC_MAX_PARAMS * sizeof(uint32_t))

#define TMECOM_IPC_MAX_WAIT_FOR_RESPONSE	TMECOM_DEFAULT_TIMEOUT

enum tmecom_ipc {
	TMECOM_IPC_TYPE_MBOX_ONLY = 0,
	TMECOM_IPC_TYPE_MBOX_SRAM = 1,
};

/*
 * Message Header structure to uniquely identify service API and get response.
 * Bit layout: ipcType(31) | msgLen(30-24) | msgType(23-16) |
 * actionId(15-8) | response(7-0)
 */
struct tmecom_ipc_header {
	uint8_t ipc_type : 1;  /* 0:MBOX_ONLY, 1:MBOX_SRAM */
	uint8_t msg_len : 7;   /* message length in mailbox */
	uint8_t msg_type;      /* command id */
	uint8_t action_id;     /* subcommand id */
	int8_t  response;      /* TME response (Success/Failure) */
} __packed;

struct tmecom_mbox_only_payload {
	uint32_t param[5]; /* Max 5 params (20 bytes) */
} __packed;

struct tmecom_sram_payload {
	uint32_t payload_ptr;
	uint32_t payload_len;
} __packed;

union tmecom_mbox_ipc_payload {
	struct tmecom_mbox_only_payload mailbox_payload;
	struct tmecom_sram_payload sram_payload;
} __packed;

/* Total 24 bytes (4 header + 20 payload) */
struct tmecom_mbox_ipc_pkt {
	struct tmecom_ipc_header msg_hdr;
	union tmecom_mbox_ipc_payload payload;
} __packed;

enum tmecom_rx_state {
	TMECOM_RX_NONE = 0,
	TMECOM_RX_PENDING = 1,
	TMECOM_RX_IN_PROGRESS = 2,
	TMECOM_RX_DONE = 3,
};

enum tmecom_tx_state {
	TMECOM_TX_NONE = 0,
	TMECOM_TX_ABORT = 1,
	TMECOM_TX_DONE = 2,
	TMECOM_TX_IN_PROGRESS = 3,
};

struct tmecom_user_cb_data {
	tmecom_notify_rx_callback cb_after_rx;
	struct tmecom_callback_data cb_data;
	uint32_t param_id;
};

struct tmecom_ctx {
	struct qcom_mbox_chan *chan;
	bool connected;
	bool tmecom_blocking;
	bool ipc_in_progress;
	bool client_buf_owned;
	enum tmecom_tx_state tx_state;
	enum tmecom_rx_state rx_state;
	enum tmecom_response remote_rsp;
	struct tmecom_user_cb_data user_data;
};

/*
 * TMECOM_IPCBUF_CARVEOUT_SIZE at the top of TZDRAM is split into two
 * cache-coherent buffers shared with TME-Lite:
 *   TMECOM_SRAM_BUF_PA   (TMECOM_IPC_BUF_PA): SRAM IPC buffer
 *   TMECOM_CLIENT_BUF_PA: client buffer, right after the SRAM buffer
 */
#define TMECOM_SRAM_BUF_PA	TMECOM_IPC_BUF_PA
#define TMECOM_CLIENT_BUF_PA	\
	(TMECOM_SRAM_BUF_PA + TMECOM_SRAM_IPC_MAX_BUF_SIZE)
#define TMECOM_CLIENT_BUF_SIZE	\
	(TMECOM_IPCBUF_CARVEOUT_SIZE - TMECOM_SRAM_IPC_MAX_BUF_SIZE)
_Static_assert(TMECOM_IPCBUF_CARVEOUT_SIZE > TMECOM_SRAM_IPC_MAX_BUF_SIZE,
	       "TMECOM carveout size must exceed SRAM IPC buffer size");
_Static_assert(TMECOM_CLIENT_BUF_SIZE >= 0x1000,
	       "Client buffer size must be at least 4KB");
/*
 * The carveout is taken from the top of TZDRAM (see TMECOM_IPC_BUF_PA); it must
 * fit within TZDRAM so it cannot overlap memory outside the secure region.
 */
_Static_assert(TMECOM_IPCBUF_CARVEOUT_SIZE < CFG_TZDRAM_SIZE,
	       "TMECOM carveout must fit within TZDRAM");

/* The IPC packet must fit the mailbox the transport negotiates. */
_Static_assert(sizeof(struct tmecom_mbox_ipc_pkt) <= TMECOM_HW_MBOX_SIZE,
	       "IPC packet must fit the hardware mailbox");

/* SRAM IPC and client buffers, shared cache-coherently with TME-Lite */
register_phys_mem(MEM_AREA_TEE_COHERENT, TMECOM_IPC_BUF_PA,
		  TMECOM_IPCBUF_CARVEOUT_SIZE);

/* Coherent virtual/physical addresses - resolved on session_start */
static struct io_pa_va sram_buf;
static struct io_pa_va client_buf;

/*
 * Serializes access to tmecom_ctx and the IPC state flags. Declared
 * separately from tmecom_ctx so that resetting the context (memset) never
 * touches the lock itself.
 */
static unsigned int tmecom_lock = SPINLOCK_UNLOCK;

static struct tmecom_ctx tmecom_ctx;
static struct tmecom_mbox_ipc_pkt ipc_mailbox;

/* Staging buffer sized for the full mailbox, so a long reply is never lost. */
static uint8_t ipc_rx_buf[TMECOM_HW_MBOX_SIZE];

TEE_Result tmecom_to_tee_result(enum tmecom_response status)
{
	switch (status) {
	case TMECOM_RSP_SUCCESS:
		return TEE_SUCCESS;
	case TMECOM_RSP_FAILURE_BAD_ADDR:
	case TMECOM_RSP_FAILURE_INVALID_ARGS:
		return TEE_ERROR_BAD_PARAMETERS;
	case TMECOM_RSP_FAILURE_CHANNEL_ERR:
	case TMECOM_RSP_FAILURE_LINK_ERR:
	case TMECOM_RSP_FAILURE_TX_ERR:
	case TMECOM_RSP_FAILURE_RX_ERR:
	case TMECOM_RSP_FAILURE_INVALID_MESSAGE:
		return TEE_ERROR_COMMUNICATION;
	case TMECOM_RSP_FAILURE_TIMEOUT:
		return TEE_ERROR_TIMEOUT;
	case TMECOM_RSP_FAILURE_BUSY:
		return TEE_ERROR_BUSY;
	case TMECOM_RSP_FAILURE_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case TMECOM_SERVICE_API_RETURNED_ERR:
		return TEE_ERROR_GENERIC;
	case TMECOM_RSP_FAILURE:
	default:
		return TEE_ERROR_GENERIC;
	}
}

void *tmecom_client_get_coherent_buf(size_t size, paddr_t *phys_addr)
{
	uint32_t exceptions = 0;

	if (!size || size > TMECOM_CLIENT_BUF_SIZE || !client_buf.va)
		return NULL;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	if (!cpu_spin_trylock(&tmecom_lock)) {
		thread_unmask_exceptions(exceptions);
		return NULL;
	}

	if (tmecom_ctx.ipc_in_progress || tmecom_ctx.client_buf_owned) {
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(exceptions);
		return NULL;
	}

	tmecom_ctx.client_buf_owned = true;
	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	if (phys_addr)
		*phys_addr = client_buf.pa;

	return (void *)client_buf.va;
}

void tmecom_client_release_buf(void)
{
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	cpu_spin_lock(&tmecom_lock);

	if (!tmecom_ctx.client_buf_owned) {
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(exceptions);
		return;
	}

	tmecom_ctx.client_buf_owned = false;
	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	/* Scrub after releasing ownership so a valid VA is guaranteed */
	if (client_buf.va)
		memset((void *)client_buf.va, 0, TMECOM_CLIENT_BUF_SIZE);
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

static bool is_server_connected(struct tmecom_ctx *ctx)
{
	return ctx && ctx->chan && ctx->connected;
}

/*
 * Wait until the transport reports any of the @wanted events.
 *
 * The mailbox framework is non-blocking by contract: it never polls or waits
 * internally, so every wait in this driver funnels through here.  The bobcat
 * QMP-Lite channel is configured for polling-only mode (itr_chip == NULL), so
 * this busy-waits on qcom_mbox_process().
 *
 * This is the only place that needs to change to adopt IRQ-assisted wakeup:
 * once a channel supplies an interrupt, qcom_mbox_enable_irq() plus a wait on
 * the notification callback replaces the spin, and the qcom_mbox_process()
 * drain below stays as-is.  Callers are unaffected.
 */
static enum tmecom_response tmecom_mbox_wait(struct tmecom_ctx *ctx,
					     uint32_t wanted,
					     uint32_t timeout_us)
{
	uint64_t t = timeout_init_us(timeout_us);
	uint32_t seen = 0;

	while (true) {
		uint32_t events = 0;

		if (qcom_mbox_process(ctx->chan, &events))
			return TMECOM_RSP_FAILURE_CHANNEL_ERR;

		seen |= events;

		if (seen & QCOM_MBOX_EVT_CONNECTED)
			ctx->connected = true;
		else if (seen & (QCOM_MBOX_EVT_DISCONNECTED |
				 QCOM_MBOX_EVT_REMOTE_RESET))
			ctx->connected = false;

		/*
		 * ERROR is sticky and unrecoverable: the channel has to be
		 * released before it can be used again.
		 */
		if (seen & QCOM_MBOX_EVT_ERROR) {
			EMSG("Mailbox reported an unrecoverable error");
			return TMECOM_RSP_FAILURE_CHANNEL_ERR;
		}

		if (seen & wanted)
			return TMECOM_RSP_SUCCESS;

		if (timeout_elapsed(t))
			return TMECOM_RSP_FAILURE_TIMEOUT;
	}
}

/*
 * Drain one response from the mailbox into the caller's payload buffer.
 *
 * Runs in the caller's context after QCOM_MBOX_EVT_RX_READY, so no
 * synchronisation against an interrupt handler is needed.
 */
static enum tmecom_response tmecom_receive_response(struct tmecom_ctx *ctx)
{
	union tmecom_mbox_ipc_payload *payload = &ipc_mailbox.payload;
	struct tmecom_ipc_header *msg_hdr = &ipc_mailbox.msg_hdr;
	struct tmecom_user_cb_data *ud = &ctx->user_data;
	size_t len = sizeof(ipc_rx_buf);
	void *payload_data = NULL;

	memset(ipc_rx_buf, 0, sizeof(ipc_rx_buf));
	memset(&ipc_mailbox, 0, sizeof(ipc_mailbox));

	if (qcom_mbox_recv(ctx->chan, ipc_rx_buf, &len)) {
		EMSG("Mailbox receive failed");
		return TMECOM_RSP_FAILURE_RX_ERR;
	}

	if (len < sizeof(struct tmecom_ipc_header)) {
		EMSG("Response too short: %zu bytes", len);
		return TMECOM_RSP_FAILURE_INVALID_MESSAGE;
	}

	memcpy(&ipc_mailbox, ipc_rx_buf,
	       MIN(len, sizeof(struct tmecom_mbox_ipc_pkt)));

	ctx->remote_rsp = (enum tmecom_response)msg_hdr->response;

	if (!ud->cb_data.generic_payload)
		return TMECOM_RSP_SUCCESS;

	if (msg_hdr->ipc_type == TMECOM_IPC_TYPE_MBOX_ONLY) {
		payload_data = &payload->mailbox_payload.param;
		memcpy(ud->cb_data.generic_payload, payload_data,
		       MIN(ud->cb_data.generic_payload_len,
			   sizeof(struct tmecom_mbox_only_payload)));
	} else {
		paddr_t pa = (paddr_t)payload->sram_payload.payload_ptr;

		payload_data = phys_to_virt(pa, MEM_AREA_TEE_COHERENT,
					    TMECOM_SRAM_IPC_MAX_BUF_SIZE);
		if (!payload_data) {
			EMSG("Failed to map SRAM response payload");
			return TMECOM_RSP_FAILURE_BAD_ADDR;
		}

		memcpy(ud->cb_data.generic_payload, payload_data,
		       MIN(ud->cb_data.generic_payload_len,
			   TMECOM_SRAM_IPC_MAX_BUF_SIZE));
	}

	return TMECOM_RSP_SUCCESS;
}

TEE_Result tmecom_client_session_start(void)
{
	enum tmecom_response res = TMECOM_RSP_SUCCESS;
	uint32_t exceptions = 0;
	size_t mtu = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (!cpu_spin_trylock(&tmecom_lock)) {
		thread_unmask_exceptions(exceptions);
		return tmecom_to_tee_result(TMECOM_RSP_FAILURE_BUSY);
	}

	if (!tmecom_ctx.chan) {
		if (qcom_mbox_request(TMECOM_MBOX_CHANNEL_NAME, NULL, NULL,
				      &tmecom_ctx.chan)) {
			EMSG("Failed to request mailbox channel \"%s\"",
			     TMECOM_MBOX_CHANNEL_NAME);
			res = TMECOM_RSP_FAILURE_LINK_ERR;
			goto exit;
		}
	}

	res = tmecom_mbox_wait(&tmecom_ctx, QCOM_MBOX_EVT_CONNECTED,
			       TMECOM_IPC_MAX_WAIT_FOR_RESPONSE);
	if (res) {
		EMSG("Mailbox did not connect to TME-Lite");
		res = TMECOM_RSP_FAILURE_CHANNEL_ERR;
		goto exit;
	}

	/*
	 * The MTU is only valid once connected. Refuse to run rather than
	 * silently truncating requests if the mailbox is smaller than the
	 * packet TME-Lite expects.
	 */
	if (qcom_mbox_get_mtu(tmecom_ctx.chan, &mtu) ||
	    mtu < sizeof(struct tmecom_mbox_ipc_pkt)) {
		EMSG("Mailbox MTU %zu too small for a %zu byte IPC packet",
		     mtu, sizeof(struct tmecom_mbox_ipc_pkt));
		res = TMECOM_RSP_FAILURE_CHANNEL_ERR;
		goto exit;
	}

	if (!sram_buf.va) {
		sram_buf.va =
			(vaddr_t)phys_to_virt(TMECOM_SRAM_BUF_PA,
					      MEM_AREA_TEE_COHERENT,
					      TMECOM_SRAM_IPC_MAX_BUF_SIZE);
		if (!sram_buf.va) {
			EMSG("Failed to get SRAM coherent VA");
			res = TMECOM_RSP_FAILURE;
			goto exit;
		}
		sram_buf.pa = TMECOM_SRAM_BUF_PA;
	}

	if (!client_buf.va) {
		client_buf.va =
			(vaddr_t)phys_to_virt(TMECOM_CLIENT_BUF_PA,
					      MEM_AREA_TEE_COHERENT,
					      TMECOM_CLIENT_BUF_SIZE);
		if (!client_buf.va) {
			EMSG("Failed to get client coherent VA");
			res = TMECOM_RSP_FAILURE;
			goto exit;
		}
		client_buf.pa = TMECOM_CLIENT_BUF_PA;
	}

exit:
	if (res) {
		qcom_mbox_release(tmecom_ctx.chan);

		/*
		 * Clear the global context while still holding the lock so a
		 * concurrent caller cannot observe a half-torn-down session.
		 * Safe now that tmecom_lock lives outside tmecom_ctx.
		 */
		memset(&tmecom_ctx, 0, sizeof(tmecom_ctx));
	}

	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	return tmecom_to_tee_result(res);
}

TEE_Result tmecom_client_session_end(void)
{
	enum tmecom_response res = TMECOM_RSP_SUCCESS;
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (!cpu_spin_trylock(&tmecom_lock)) {
		thread_unmask_exceptions(exceptions);
		return tmecom_to_tee_result(TMECOM_RSP_FAILURE_BUSY);
	}

	/* Refuse to tear down while an IPC transaction is in flight */
	if (tmecom_ctx.ipc_in_progress || tmecom_ctx.client_buf_owned) {
		res = TMECOM_RSP_FAILURE_BUSY;
		goto unlock_exit;
	}

	qcom_mbox_release(tmecom_ctx.chan);

	if (sram_buf.va)
		memset((void *)sram_buf.va, 0, TMECOM_SRAM_IPC_MAX_BUF_SIZE);
	if (client_buf.va)
		memset((void *)client_buf.va, 0, TMECOM_CLIENT_BUF_SIZE);

	/*
	 * Always clear the global context so a subsequent session_start never
	 * operates on a stale channel handle. tmecom_lock lives outside
	 * tmecom_ctx so this is safe under the lock.
	 */
	memset(&tmecom_ctx, 0, sizeof(tmecom_ctx));

unlock_exit:
	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	return tmecom_to_tee_result(res);
}

TEE_Result
tmecom_client_send_message(uint32_t tme_msg_uid, uint32_t tme_msg_param_id,
			   bool is_blocking, uint32_t timeout,
			   void *generic_payload, uint32_t generic_payload_len,
			   tmecom_notify_rx_callback cb_api, void *user_data,
			   enum tmecom_response *tme_err)
{
	union tmecom_mbox_ipc_payload *ipc_payload = &ipc_mailbox.payload;
	struct tmecom_ipc_header *msg_hdr = &ipc_mailbox.msg_hdr;
	struct tmecom_user_cb_data *ud = &tmecom_ctx.user_data;
	uint32_t hdr_len = sizeof(struct tmecom_ipc_header);
	enum tmecom_response res = TMECOM_RSP_SUCCESS;
	enum tmecom_response rsp = TMECOM_RSP_SUCCESS;
	void *payload_data = NULL;
	uint32_t exceptions = 0;

	if (!generic_payload || !generic_payload_len) {
		res = TMECOM_RSP_FAILURE_INVALID_ARGS;
		goto exit;
	}

	if (!is_server_connected(&tmecom_ctx)) {
		DMSG("Server not connected: msg uid=0x%x", tme_msg_uid);
		res = TMECOM_RSP_FAILURE;
		goto exit;
	}

	if (!is_blocking && !cb_api) {
		res = TMECOM_RSP_FAILURE_INVALID_ARGS;
		goto exit;
	}

	/*
	 * Atomically check-and-set ipc_in_progress under the spinlock.
	 * The lock is released immediately after; all IPC work runs lock-free.
	 */
	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	if (!cpu_spin_trylock(&tmecom_lock)) {
		thread_unmask_exceptions(exceptions);
		res = TMECOM_RSP_FAILURE_BUSY;
		goto exit;
	}

	if (tmecom_ctx.ipc_in_progress) {
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(exceptions);
		res = TMECOM_RSP_FAILURE_BUSY;
		goto exit;
	}

	tmecom_ctx.ipc_in_progress = true;
	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	tmecom_ctx.tx_state = TMECOM_TX_NONE;
	tmecom_ctx.rx_state = TMECOM_RX_NONE;
	tmecom_ctx.remote_rsp = TMECOM_RSP_SUCCESS;

	ud->cb_after_rx = cb_api;
	ud->cb_data.user_data = user_data;
	ud->cb_data.generic_payload = generic_payload;
	ud->cb_data.generic_payload_len = generic_payload_len;
	ud->cb_data.tme_msg_uid = tme_msg_uid;
	ud->param_id = tme_msg_param_id;
	tmecom_ctx.tmecom_blocking = is_blocking;

	memset(&ipc_mailbox, 0, sizeof(struct tmecom_mbox_ipc_pkt));
	memset((void *)sram_buf.va, 0, TMECOM_SRAM_IPC_MAX_BUF_SIZE);

	if (hdr_len + generic_payload_len <= TMECOM_MBOX_IPC_PACKET_SIZE) {
		msg_hdr->ipc_type = TMECOM_IPC_TYPE_MBOX_ONLY;
		msg_hdr->msg_len = generic_payload_len;
		payload_data = &ipc_payload->mailbox_payload.param;
		memcpy(payload_data, generic_payload,
		       MIN(generic_payload_len,
			   sizeof(struct tmecom_mbox_only_payload)));
	} else if (generic_payload_len <= TMECOM_SRAM_IPC_MAX_BUF_SIZE) {
		msg_hdr->ipc_type = TMECOM_IPC_TYPE_MBOX_SRAM;
		msg_hdr->msg_len = sizeof(struct tmecom_sram_payload);
		ipc_payload->sram_payload.payload_len = generic_payload_len;
		ipc_payload->sram_payload.payload_ptr = (uint32_t)sram_buf.pa;
		memcpy((void *)sram_buf.va, generic_payload,
		       MIN(generic_payload_len, TMECOM_SRAM_IPC_MAX_BUF_SIZE));
	} else {
		res = TMECOM_RSP_FAILURE_INVALID_ARGS;
		goto exit;
	}

	msg_hdr->msg_type = TME_MSG_UID_MSG_TYPE(tme_msg_uid);
	msg_hdr->action_id = TME_MSG_UID_ACTION_ID(tme_msg_uid);

	tmecom_ctx.tx_state = TMECOM_TX_IN_PROGRESS;
	if (qcom_mbox_send(tmecom_ctx.chan, &ipc_mailbox,
			   sizeof(struct tmecom_mbox_ipc_pkt))) {
		EMSG("Mailbox send failed: msg uid=0x%x", tme_msg_uid);
		res = TMECOM_RSP_FAILURE_TX_ERR;
		goto exit;
	}

	res = tmecom_mbox_wait(&tmecom_ctx, QCOM_MBOX_EVT_TX_DONE,
			       TMECOM_IPC_MAX_WAIT_FOR_RESPONSE);
	if (res) {
		EMSG("TME-Lite did not consume the request");
		tmecom_ctx.tx_state = TMECOM_TX_ABORT;
		res = TMECOM_RSP_FAILURE_TX_ERR;
		goto exit;
	}
	tmecom_ctx.tx_state = TMECOM_TX_DONE;

	/*
	 * The response is collected here for both blocking and non-blocking
	 * callers.  A polling-only transport has no interrupt to deliver a
	 * late reply on, so a non-blocking request cannot return before its
	 * response arrives; what it still gets is delivery through @cb_api
	 * rather than through @generic_payload alone.  Callers that pass
	 * is_blocking = false therefore keep working unchanged, and become
	 * genuinely asynchronous once the channel gains an interrupt.
	 */
	timeout = timeout ? timeout : TMECOM_DEFAULT_TIMEOUT;

	tmecom_ctx.rx_state = TMECOM_RX_PENDING;
	res = tmecom_mbox_wait(&tmecom_ctx, QCOM_MBOX_EVT_RX_READY, timeout);
	if (res) {
		EMSG("Timeout waiting for a response from TME-Lite");
		res = TMECOM_RSP_FAILURE_RX_ERR;
		goto exit;
	}

	tmecom_ctx.rx_state = TMECOM_RX_IN_PROGRESS;
	res = tmecom_receive_response(&tmecom_ctx);
	if (res)
		goto exit;
	tmecom_ctx.rx_state = TMECOM_RX_DONE;

	rsp = tmecom_ctx.remote_rsp;
	if (rsp) {
		if (tme_err)
			*tme_err = rsp;
		DMSG("Response from TME: %d", rsp);
		res = TMECOM_SERVICE_API_RETURNED_ERR;
	}

	tmecom_ctx.ipc_in_progress = false;

	if (!is_blocking && ud->cb_after_rx)
		ud->cb_after_rx(rsp, &ud->cb_data);

	return tmecom_to_tee_result(res);

exit:
	/*
	 * Clear in-progress on any real error.  Skip for BUSY — those paths
	 * never set ipc_in_progress so it must not be touched.
	 */
	if (res && res != TMECOM_RSP_FAILURE_BUSY)
		tmecom_ctx.ipc_in_progress = false;

	if (tme_err)
		*tme_err = res;

	return tmecom_to_tee_result(res);
}

early_init(tmecom_client_session_start);
