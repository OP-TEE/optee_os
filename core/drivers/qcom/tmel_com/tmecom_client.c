// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/spinlock.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "tmecom_client.h"
#include "glink_com.h"
#include "tmemessages_uids.h"
#include <initcall.h>

/*
 * IPC Packet Definitions
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

/* Total 32 bytes (24 payload + 8 QMP control) */
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

struct tmecom_glink_cfg {
	const char *remote;
	const char *channel;
};

struct tmecom_glink_ctx {
	const struct tmecom_glink_cfg *cfg;
	struct glink_channel_ctx *ch_handle;
	bool link_up;
	struct glink_link_id link_id;
	enum glink_channel_event_type glink_state;
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

/* SRAM IPC and client buffers, shared cache-coherently with TME-Lite */
register_phys_mem(MEM_AREA_TEE_COHERENT, TMECOM_IPC_BUF_PA,
		  TMECOM_IPCBUF_CARVEOUT_SIZE);

/* Coherent virtual/physical addresses - resolved on session_start */
static struct io_pa_va sram_buf;
static struct io_pa_va client_buf;

/*
 * Serializes access to glink_ctx and the IPC state flags. Declared
 * separately from glink_ctx so that resetting the context (memset) never
 * touches the lock itself.
 */
static unsigned int tmecom_lock = SPINLOCK_UNLOCK;

static struct tmecom_glink_ctx glink_ctx;
static struct tmecom_mbox_ipc_pkt ipc_mailbox;

static const struct tmecom_glink_cfg tmecom_cfg = {
	.remote = "tme",
	.channel = "tmeRequest",
};

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

	if (glink_ctx.ipc_in_progress || glink_ctx.client_buf_owned) {
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(exceptions);
		return NULL;
	}

	glink_ctx.client_buf_owned = true;
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

	if (!glink_ctx.client_buf_owned) {
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(exceptions);
		return;
	}

	WRITE_ONCE(glink_ctx.client_buf_owned, false);
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

static bool is_server_connected(struct tmecom_glink_ctx *ctx)
{
	return ctx && ctx->link_up && ctx->ch_handle &&
	       ctx->glink_state == GLINK_CONNECTED;
}

static void tmecom_notify_rx(struct glink_channel_ctx *handle,
			     const void *priv,
			     const void *pkt_priv,
			     const void *ptr,
			     size_t size,
			     size_t intents_used)
{
	struct tmecom_user_cb_data ud = { 0 };
	tmecom_notify_rx_callback send_rsp_cb = NULL;
	enum tmecom_response tme_rsp = TMECOM_RSP_FAILURE;
	struct tmecom_ipc_header *msg_hdr = &ipc_mailbox.msg_hdr;
	union tmecom_mbox_ipc_payload *payload = &ipc_mailbox.payload;
	enum glink_err_type rx_done_ret = GLINK_STATUS_SUCCESS;
	enum tmecom_ipc ipc_type = TMECOM_IPC_TYPE_MBOX_ONLY;
	void *user_payload = NULL;
	void *payload_data = NULL;
	size_t user_payload_len = 0;

	(void)handle;
	(void)priv;
	(void)pkt_priv;
	(void)intents_used;

	if (!ptr)
		return;

	/*
	 * Mark RX in-progress before touching user_data so a timed-out sender
	 * can detect an in-flight ISR (rx_state != DONE) and drain it.
	 */
	WRITE_ONCE(glink_ctx.rx_state, TMECOM_RX_IN_PROGRESS);

	/* Ensure we observe all user_data writes from send_message */
	dsb();
	memcpy(&ud, &glink_ctx.user_data, sizeof(ud));
	user_payload = ud.cb_data.generic_payload;
	user_payload_len = ud.cb_data.generic_payload_len;

	if (!user_payload) {
		rx_done_ret = glink_rx_done(glink_ctx.ch_handle, ptr, false);
		if (rx_done_ret != GLINK_STATUS_SUCCESS)
			EMSG("glink_rx_done failed (no payload): %d",
			     rx_done_ret);
		WRITE_ONCE(glink_ctx.rx_state, TMECOM_RX_DONE);
		return;
	}

	memcpy(&ipc_mailbox, ptr,
	       MIN(size, sizeof(struct tmecom_mbox_ipc_pkt)));

	tme_rsp = (enum tmecom_response)msg_hdr->response;
	WRITE_ONCE(glink_ctx.remote_rsp, tme_rsp);

	ipc_type = msg_hdr->ipc_type;
	if (ipc_type == TMECOM_IPC_TYPE_MBOX_ONLY) {
		payload_data = &payload->mailbox_payload.param;
		memcpy(user_payload, payload_data,
		       MIN(user_payload_len,
			   sizeof(struct tmecom_mbox_only_payload)));
	} else if (ipc_type == TMECOM_IPC_TYPE_MBOX_SRAM) {
		paddr_t pa = (paddr_t)payload->sram_payload.payload_ptr;

		payload_data = phys_to_virt(pa, MEM_AREA_TEE_COHERENT,
					    TMECOM_SRAM_IPC_MAX_BUF_SIZE);
		if (payload_data)
			memcpy(user_payload, payload_data,
			       MIN(user_payload_len,
				   TMECOM_SRAM_IPC_MAX_BUF_SIZE));
	}

	rx_done_ret = glink_rx_done(glink_ctx.ch_handle, ptr, false);
	if (rx_done_ret != GLINK_STATUS_SUCCESS)
		EMSG("glink_rx_done failed: %d", rx_done_ret);

	WRITE_ONCE(glink_ctx.rx_state, TMECOM_RX_DONE);

	if (!glink_ctx.tmecom_blocking) {
		/*
		 * Clear ipc_in_progress atomically.  On SMP another CPU may
		 * briefly hold the lock (e.g. inside get_coherent_buf or
		 * release_buf), so spin until we get it rather than trylock.
		 */
		uint32_t ex = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

		cpu_spin_lock(&tmecom_lock);
		WRITE_ONCE(glink_ctx.ipc_in_progress, false);
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(ex);

		send_rsp_cb = ud.cb_after_rx;
		if (send_rsp_cb) {
			send_rsp_cb(tme_rsp, &ud.cb_data);
			return;
		}
	}
}

static void tmecom_notify_tx_done(struct glink_channel_ctx *handle,
				  const void *priv,
				  const void *pkt_priv,
				  const void *ptr,
				  size_t size)
{
	(void)handle;
	(void)priv;
	(void)pkt_priv;
	(void)ptr;
	(void)size;

	WRITE_ONCE(glink_ctx.tx_state, TMECOM_TX_DONE);
}

static void tmecom_notify_tx_abort(struct glink_channel_ctx *handle,
				   const void *priv,
				   const void *pkt_priv)
{
	(void)handle;
	(void)priv;
	(void)pkt_priv;

	WRITE_ONCE(glink_ctx.tx_state, TMECOM_TX_ABORT);
}

static void tmecom_notify_channel_state_isr(struct glink_channel_ctx *handle,
					    const void *priv,
					    enum glink_channel_event_type event)
{
	struct tmecom_glink_ctx *ctx = (struct tmecom_glink_ctx *)priv;
	enum glink_err_type ret = GLINK_STATUS_SUCCESS;

	(void)handle;

	if (!ctx)
		return;

	switch (event) {
	case GLINK_LOCAL_DISCONNECTED:
		ctx->ch_handle = NULL;
		ctx->glink_state = GLINK_LOCAL_DISCONNECTED;
		break;

	case GLINK_CONNECTED:
		ctx->glink_state = GLINK_CONNECTED;
		break;

	case GLINK_REMOTE_DISCONNECTED:
		ctx->glink_state = GLINK_REMOTE_DISCONNECTED;
		ret = glink_close(ctx->ch_handle);
		ctx->ch_handle = NULL;
		if (ret != GLINK_STATUS_SUCCESS)
			EMSG("glink_close failed: %d", ret);
		break;

	default:
		break;
	}
}

static void tmecom_notify_link_state_isr(struct glink_link_info *link_info,
					 void *priv)
{
	struct tmecom_glink_ctx *ctx = (struct tmecom_glink_ctx *)priv;
	enum glink_err_type ret = GLINK_STATUS_SUCCESS;
	struct glink_open_config ch_cfg = { };

	if (!ctx || !link_info)
		return;

	if (link_info->link_state == GLINK_LINK_STATE_UP) {
		if (ctx->ch_handle) {
			EMSG("Channel not fully closed");
			return;
		}

		ctx->link_up = true;

		ch_cfg.remote_ss = ctx->cfg->remote;
		ch_cfg.name = ctx->cfg->channel;
		ch_cfg.priv = ctx;
		ch_cfg.notify_state = tmecom_notify_channel_state_isr;
		ch_cfg.notify_rx = tmecom_notify_rx;
		ch_cfg.notify_tx_done = tmecom_notify_tx_done;
		ch_cfg.notify_tx_abort = tmecom_notify_tx_abort;

		ret = glink_open(&ch_cfg, &ctx->ch_handle);
		if (ret != GLINK_STATUS_SUCCESS || !ctx->ch_handle) {
			EMSG("Channel open failed: %d", ret);
			ctx->ch_handle = NULL;
		}
	} else if (link_info->link_state == GLINK_LINK_STATE_DOWN) {
		ctx->link_up = false;
	}
}

TEE_Result tmecom_client_session_start(void)
{
	enum glink_err_type glink_ret = GLINK_STATUS_SUCCESS;
	enum tmecom_response res = TMECOM_RSP_SUCCESS;
	uint32_t exceptions = 0;
	uint64_t t = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (!cpu_spin_trylock(&tmecom_lock)) {
		thread_unmask_exceptions(exceptions);
		return tmecom_to_tee_result(TMECOM_RSP_FAILURE_BUSY);
	}

	WRITE_ONCE(glink_ctx.glink_state, GLINK_LOCAL_DISCONNECTED);

	if (!glink_ctx.link_up) {
		glink_init();

		glink_ctx.cfg = &tmecom_cfg;

		glink_link_id_struct_init(&glink_ctx.link_id);
		glink_ctx.link_id.remote_ss = glink_ctx.cfg->remote;
		glink_ctx.link_id.link_notifier = tmecom_notify_link_state_isr;

		glink_ret = glink_register_link_state_cb(&glink_ctx.link_id,
							 &glink_ctx);
		if (glink_ret != GLINK_STATUS_SUCCESS) {
			EMSG("Link state cb register failed: %d", glink_ret);
			res = TMECOM_RSP_FAILURE_LINK_ERR;
			goto exit;
		}
	}

	t = timeout_init_us(TMECOM_IPC_MAX_WAIT_FOR_RESPONSE);
	while (READ_ONCE(glink_ctx.glink_state) == GLINK_LOCAL_DISCONNECTED) {
		if (timeout_elapsed(t))
			break;
	}

	if (READ_ONCE(glink_ctx.glink_state) != GLINK_CONNECTED) {
		EMSG("GLink not connected (state=%d)", glink_ctx.glink_state);
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
		struct glink_link_notify *handle = glink_ctx.link_id.handle;

		if (handle)
			glink_deregister_link_state_cb(handle);

		/*
		 * Clear the global context while still holding the lock so a
		 * concurrent caller cannot observe a half-torn-down session.
		 * Safe now that tmecom_lock lives outside glink_ctx.
		 */
		memset(&glink_ctx, 0, sizeof(glink_ctx));
	}

	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	return tmecom_to_tee_result(res);
}

TEE_Result tmecom_client_session_end(void)
{
	enum glink_err_type glink_ret = GLINK_STATUS_SUCCESS;
	enum tmecom_response res = TMECOM_RSP_SUCCESS;
	uint32_t exceptions = 0;
	uint64_t t = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (!cpu_spin_trylock(&tmecom_lock)) {
		thread_unmask_exceptions(exceptions);
		return tmecom_to_tee_result(TMECOM_RSP_FAILURE_BUSY);
	}

	/* Refuse to tear down while an IPC transaction is in flight */
	if (glink_ctx.ipc_in_progress || glink_ctx.client_buf_owned) {
		res = TMECOM_RSP_FAILURE_BUSY;
		goto unlock_exit;
	}

	glink_ret = glink_close(glink_ctx.ch_handle);
	if (glink_ret != GLINK_STATUS_SUCCESS) {
		EMSG("Channel close failed: %d", glink_ret);
		res = TMECOM_RSP_FAILURE_LINK_ERR;
		goto clear_and_exit;
	}

	glink_ret = glink_deregister_link_state_cb(glink_ctx.link_id.handle);
	if (glink_ret != GLINK_STATUS_SUCCESS) {
		EMSG("Link state cb de-register failed: %d", glink_ret);
		res = TMECOM_RSP_FAILURE_LINK_ERR;
		goto clear_and_exit;
	}

	t = timeout_init_us(TMECOM_IPC_MAX_WAIT_FOR_RESPONSE);
	while (READ_ONCE(glink_ctx.glink_state) != GLINK_LOCAL_DISCONNECTED) {
		if (timeout_elapsed(t))
			break;
	}

	if (sram_buf.va)
		memset((void *)sram_buf.va, 0, TMECOM_SRAM_IPC_MAX_BUF_SIZE);
	if (client_buf.va)
		memset((void *)client_buf.va, 0, TMECOM_CLIENT_BUF_SIZE);

clear_and_exit:
	/*
	 * Always clear the global context on exit, regardless of whether
	 * glink_close or glink_deregister_link_state_cb failed, to prevent
	 * a subsequent session_start from operating on stale handles.
	 * tmecom_lock lives outside glink_ctx so this is safe under the lock.
	 */
	memset(&glink_ctx, 0, sizeof(glink_ctx));

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
	struct tmecom_user_cb_data *ud = &glink_ctx.user_data;
	uint32_t hdr_len = sizeof(struct tmecom_ipc_header);
	enum tmecom_response res = TMECOM_RSP_SUCCESS;
	enum tmecom_response rsp = TMECOM_RSP_SUCCESS;
	void *payload_data = NULL;
	uint32_t exceptions = 0;
	uint32_t tx_flags = 0;
	void *pkt_priv = NULL;
	uint64_t t = 0;

	if (!generic_payload || !generic_payload_len) {
		res = TMECOM_RSP_FAILURE_INVALID_ARGS;
		goto exit;
	}

	if (!is_server_connected(&glink_ctx)) {
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

	if (glink_ctx.ipc_in_progress) {
		cpu_spin_unlock(&tmecom_lock);
		thread_unmask_exceptions(exceptions);
		res = TMECOM_RSP_FAILURE_BUSY;
		goto exit;
	}

	glink_ctx.ipc_in_progress = true;
	cpu_spin_unlock(&tmecom_lock);
	thread_unmask_exceptions(exceptions);

	WRITE_ONCE(glink_ctx.tx_state, TMECOM_TX_NONE);
	WRITE_ONCE(glink_ctx.rx_state, TMECOM_RX_NONE);

	WRITE_ONCE(ud->cb_after_rx, cb_api);
	WRITE_ONCE(ud->cb_data.user_data, user_data);
	WRITE_ONCE(ud->cb_data.generic_payload, generic_payload);
	WRITE_ONCE(ud->cb_data.generic_payload_len, generic_payload_len);
	WRITE_ONCE(ud->cb_data.tme_msg_uid, tme_msg_uid);
	WRITE_ONCE(ud->param_id, tme_msg_param_id);
	WRITE_ONCE(glink_ctx.tmecom_blocking, is_blocking);
	dsb();

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

	WRITE_ONCE(glink_ctx.tx_state, TMECOM_TX_IN_PROGRESS);
	res = (enum tmecom_response)glink_tx(glink_ctx.ch_handle, pkt_priv,
					     &ipc_mailbox,
					     sizeof(struct tmecom_mbox_ipc_pkt),
					     tx_flags);
	if (res != (enum tmecom_response)GLINK_STATUS_SUCCESS) {
		EMSG("glink_tx failed: %d", res);
		res = TMECOM_RSP_FAILURE_TX_ERR;
		goto exit;
	}

	t = timeout_init_us(TMECOM_IPC_MAX_WAIT_FOR_RESPONSE);
	while (READ_ONCE(glink_ctx.tx_state) == TMECOM_TX_IN_PROGRESS) {
		if (timeout_elapsed(t))
			break;
	}

	if (READ_ONCE(glink_ctx.tx_state) != TMECOM_TX_DONE) {
		EMSG("Invalid tx_state: %d", glink_ctx.tx_state);
		res = TMECOM_RSP_FAILURE_TX_ERR;
		goto exit;
	}

	if (is_blocking) {
		timeout = timeout ? timeout : TMECOM_DEFAULT_TIMEOUT;
		t = timeout_init_us(timeout);
		while (READ_ONCE(glink_ctx.rx_state) != TMECOM_RX_DONE) {
			if (timeout_elapsed(t)) {
				EMSG("Timeout waiting for rx_done");
				/*
				 * Drop the payload pointer so a late ISR hits
				 * the !user_payload guard, then drain any ISR
				 * already past it before clearing in-progress.
				 */
				WRITE_ONCE(ud->cb_data.generic_payload, NULL);
				dsb();
				while (READ_ONCE(glink_ctx.rx_state) ==
				       TMECOM_RX_IN_PROGRESS)
					;

				res = TMECOM_RSP_FAILURE_RX_ERR;
				goto exit;
			}
		}

		rsp = READ_ONCE(glink_ctx.remote_rsp);
		if (rsp) {
			if (tme_err)
				*tme_err = rsp;
			DMSG("Response from TME: %d", rsp);
			res = TMECOM_SERVICE_API_RETURNED_ERR;
		}

		WRITE_ONCE(glink_ctx.ipc_in_progress, false);
		return tmecom_to_tee_result(res);
	}

exit:
	/*
	 * Clear in-progress on any real error.  Skip for BUSY — those paths
	 * never set ipc_in_progress so it must not be touched.
	 * Skip for res == 0 (non-blocking success) — notify_rx clears it.
	 */
	if (res && res != TMECOM_RSP_FAILURE_BUSY)
		WRITE_ONCE(glink_ctx.ipc_in_progress, false);

	if (tme_err)
		*tme_err = res;

	return tmecom_to_tee_result(res);
}

early_init(tmecom_client_session_start);
