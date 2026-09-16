// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QMP (Qualcomm Message Protocol) transport backend.
 *
 * Local endpoint:  SCORE (macro/slave)  — this firmware (S-EL1)
 * Remote endpoint: MCORE (micro/master) — the remote processor (e.g. TME)
 *
 * The remote master initialises the shared descriptor and mailbox layout
 * asynchronously.  init() always succeeds; process() discovers the layout
 * when the initialisation signature (QMP_MAGIC) is first observed.
 *
 * Shared memory layout (offsets from desc_base)
 * ----------------------------------------------
 *   [0]         magic         (uint32_t) — QMP_MAGIC ("MAIL")
 *   [4]         core_version  (uint32_t) — master protocol version
 *   [8]         core_features (uint32_t) — master feature flags
 *   [12,  36)   MCORE endpoint descriptor (6 x uint32_t)
 *   [36,  60)   SCORE endpoint descriptor (6 x uint32_t)
 *   [60, 188)   reserved / padding
 *   [188, ...)  mailbox regions at master-written offsets
 *
 * Each endpoint descriptor contains (relative offsets):
 *   [+0]  LINK_STATE     — current link state (DOWN or UP)
 *   [+4]  LINK_STATE_ACK — acknowledgment of the remote's link state
 *   [+8]  CH_STATE       — current channel state (DISCONNECTED or CONNECTED)
 *   [+12] CH_STATE_ACK   — acknowledgment of the remote's channel state
 *   [+16] MBOX_SIZE      — size of this endpoint's mailbox region in bytes
 *   [+20] MBOX_OFFSET    — offset of this endpoint's mailbox from desc_base
 *
 * Acknowledgment field ownership
 * --------------------------------
 *   MCORE descriptor: LINK_STATE_ACK and CH_STATE_ACK are written by SCORE.
 *   SCORE descriptor: LINK_STATE_ACK and CH_STATE_ACK are written by MCORE.
 *
 * Mailbox region layout
 * ---------------------
 *   [+0] msg_len  (uint32_t) — 0 = empty; >0 = message present
 *   [+4] payload  (msg_len bytes)
 *
 * Memory ordering
 * ---------------
 * dsb() (data synchronization barrier) is used throughout to enforce
 * ordering between shared-memory writes and the doorbell signal, and
 * between the msg_len observation and payload reads.  dsb() is a superset
 * of the TF-A dmbst()/dmbld()/dmbsy() barriers used in the original code.
 *
 * Error codes
 * -----------
 * All operations return TEE_Result directly.  No errno translation is
 * performed; the framework core passes results through to callers unchanged.
 */

#include <string.h>

#include <arm.h>
#include <io.h>
#include <tee_api_types.h>
#include <trace.h>

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <drivers/qcom/mbox/qcom_mbox_qmp.h>
#include "qcom_mbox_private.h"

/* QMP protocol constants. */
#define QMP_MAGIC		UINT32_C(0x4D41494C)
#define QMP_VERSION		1U
#define QMP_FEATURES		UINT32_C(0x0)

#define QMP_LINK_DOWN		UINT32_C(0xFFFF0000)
#define QMP_LINK_UP		UINT32_C(0x0000FFFF)

#define QMP_CH_DISCONNECTED	UINT32_C(0xFFFF0000)
#define QMP_CH_CONNECTED	UINT32_C(0x0000FFFF)

/* Descriptor header layout (offsets from desc_base). */
#define QMP_OFF_MAGIC			0U
#define QMP_OFF_CORE_VERSION		4U
#define QMP_OFF_CORE_FEATURES		8U
#define QMP_OFF_MCORE_LINK_STATE	12U
#define QMP_OFF_SCORE_LINK_STATE	36U
#define QMP_DESC_HEADER_SIZE		188U

/* Per-endpoint field offsets relative to the endpoint descriptor base. */
#define QMP_EP_LINK_STATE_OFF		0U
#define QMP_EP_LINK_STATE_ACK_OFF	4U
#define QMP_EP_CH_STATE_OFF		8U
#define QMP_EP_CH_STATE_ACK_OFF		12U
#define QMP_EP_MBOX_SIZE_OFF		16U
#define QMP_EP_MBOX_OFFSET_OFF		20U

/* Mailbox region layout: msg_len at offset 0, payload at offset 4. */
#define QMP_MBOX_MSG_LEN_OFF		0U
#define QMP_MBOX_MSG_DATA_OFF		4U

/* Convenience aliases mapping local/remote roles to descriptor offsets. */
#define QMP_LOCAL_EP_OFF	QMP_OFF_SCORE_LINK_STATE
#define QMP_REMOTE_EP_OFF	QMP_OFF_MCORE_LINK_STATE

/* --------------------------------------------------------------------------
 * Low-level MMIO helpers
 * --------------------------------------------------------------------------
 */

static void qmp_mbox_write(vaddr_t dst, const void *src, size_t len)
{
	const uint8_t *buf = (const uint8_t *)src;
	uint32_t full = (uint32_t)(len >> 2U);
	uint32_t rem  = (uint32_t)(len & 3U);
	uint32_t word = 0;
	uint32_t i = 0;

	for (i = 0U; i < full; i++) {
		memcpy(&word, buf, sizeof(word));
		io_write32(dst, word);
		buf += sizeof(uint32_t);
		dst += sizeof(uint32_t);
	}
	if (rem != 0U) {
		word = 0U;
		memcpy(&word, buf, rem);
		io_write32(dst, word);
	}
}

static void qmp_mbox_read(void *dst, vaddr_t src, size_t len)
{
	uint8_t *buf = (uint8_t *)dst;
	uint32_t full = (uint32_t)(len >> 2U);
	uint32_t rem  = (uint32_t)(len & 3U);
	uint32_t word = 0;
	uint32_t i = 0;

	for (i = 0U; i < full; i++) {
		word = io_read32(src);
		memcpy(buf, &word, sizeof(word));
		buf += sizeof(uint32_t);
		src += sizeof(uint32_t);
	}
	if (rem != 0U) {
		word = io_read32(src);
		memcpy(buf, &word, rem);
	}
}

static struct qcom_mbox_qmp_priv *qmp_priv(struct qcom_mbox_chan *chan)
{
	return (struct qcom_mbox_qmp_priv *)chan->cfg->transport_priv;
}

static void qmp_signal_remote(const struct qcom_mbox_qmp_config *cfg)
{
	dsb();
	if (cfg->remote_signal.reg != 0U)
		io_write32(cfg->remote_signal.reg, cfg->remote_signal.value);
}

static bool qmp_validate_layout(struct qcom_mbox_chan *chan,
				struct qcom_mbox_qmp_priv *priv)
{
	const struct qcom_mbox_qmp_config *cfg = priv->cfg;
	vaddr_t base = cfg->desc_base;
	vaddr_t local_desc = 0;
	vaddr_t remote_desc = 0;
	uint32_t lsz = 0;
	uint32_t loff = 0;
	uint32_t rsz = 0;
	uint32_t roff = 0;
	uint32_t lpay = 0;
	uint32_t rpay = 0;

	if (cfg->shared_size < QMP_DESC_HEADER_SIZE)
		return false;

	local_desc  = base + QMP_LOCAL_EP_OFF;
	remote_desc = base + QMP_REMOTE_EP_OFF;

	lsz  = io_read32(local_desc  + QMP_EP_MBOX_SIZE_OFF);
	loff = io_read32(local_desc  + QMP_EP_MBOX_OFFSET_OFF);
	rsz  = io_read32(remote_desc + QMP_EP_MBOX_SIZE_OFF);
	roff = io_read32(remote_desc + QMP_EP_MBOX_OFFSET_OFF);

	if (lsz <= QMP_MBOX_MSG_DATA_OFF || rsz <= QMP_MBOX_MSG_DATA_OFF)
		return false;
	if (((uint64_t)loff + lsz) > cfg->shared_size)
		return false;
	if (((uint64_t)roff + rsz) > cfg->shared_size)
		return false;
	if (loff < QMP_DESC_HEADER_SIZE)
		return false;
	if (roff < QMP_DESC_HEADER_SIZE)
		return false;

	lpay = lsz - QMP_MBOX_MSG_DATA_OFF;
	rpay = rsz - QMP_MBOX_MSG_DATA_OFF;

	priv->local_desc_base     = local_desc;
	priv->remote_desc_base    = remote_desc;
	priv->local_mbox_base     = base + loff;
	priv->remote_mbox_base    = base + roff;
	priv->local_payload_size  = lpay;
	priv->remote_payload_size = rpay;

	chan->mtu = (size_t)lpay;
	priv->layout_valid = true;

	(void)chan;
	return true;
}

/* --------------------------------------------------------------------------
 * Link state machine helpers
 * --------------------------------------------------------------------------
 */

static void qmp_reset_to_link_down(struct qcom_mbox_chan *chan,
				   struct qcom_mbox_qmp_priv *priv)
{
	/*
	 * Guard MMIO writes: local_desc_base is 0 before layout discovery.
	 * Skip writes in that case to avoid a NULL-address fault.
	 */
	if (priv->local_desc_base != 0U) {
		io_write32(priv->local_desc_base + QMP_EP_LINK_STATE_OFF,
			   QMP_LINK_DOWN);
		io_write32(priv->local_desc_base + QMP_EP_CH_STATE_OFF,
			   QMP_CH_DISCONNECTED);
	}
	priv->state = QMP_STATE_LINK_DOWN;
	priv->tx_pending = false;
	chan->mtu = 0U;
}

static void qmp_link_teardown(struct qcom_mbox_chan *chan,
			      struct qcom_mbox_qmp_priv *priv,
			      bool ch_was_connected)
{
	const struct qcom_mbox_qmp_config *cfg = priv->cfg;

	if (ch_was_connected) {
		io_write32(priv->local_desc_base + QMP_EP_LINK_STATE_OFF,
			   QMP_LINK_DOWN);
		qmp_signal_remote(cfg);
	}
	qmp_reset_to_link_down(chan, priv);
}

/* --------------------------------------------------------------------------
 * Per-state process handlers — all return TEE_Result
 * --------------------------------------------------------------------------
 */

static TEE_Result qmp_handle_link_down(struct qcom_mbox_chan *chan,
				       struct qcom_mbox_qmp_priv *priv)
{
	const struct qcom_mbox_qmp_config *cfg = priv->cfg;
	uint32_t magic = 0;
	uint32_t version = 0;
	uint32_t features = 0;

	magic = io_read32(cfg->desc_base + QMP_OFF_MAGIC);
	if (magic != QMP_MAGIC)
		return TEE_SUCCESS;  /* Remote not yet initialised. */

	version = io_read32(cfg->desc_base + QMP_OFF_CORE_VERSION);
	if (version != QMP_VERSION) {
		EMSG("qcom_mbox_qmp: unsupported version %u (expected %u)",
		     version, QMP_VERSION);
		return TEE_ERROR_COMMUNICATION;
	}

	features = io_read32(cfg->desc_base + QMP_OFF_CORE_FEATURES);
	if (features != QMP_FEATURES) {
		EMSG("qcom_mbox_qmp: unsupported features 0x%08X (exp 0x%08X)",
		     features, QMP_FEATURES);
		return TEE_ERROR_COMMUNICATION;
	}

	if (!qmp_validate_layout(chan, priv)) {
		EMSG("qcom_mbox_qmp: invalid shared layout");
		return TEE_ERROR_COMMUNICATION;
	}

	io_write32(priv->local_desc_base + QMP_EP_LINK_STATE_OFF, QMP_LINK_UP);
	qmp_signal_remote(cfg);
	priv->state = QMP_STATE_LINK_NEGOTIATION;
	return TEE_SUCCESS;
}

static TEE_Result qmp_handle_link_negotiation(struct qcom_mbox_chan *chan,
					      struct qcom_mbox_qmp_priv *priv)
{
	const struct qcom_mbox_qmp_config *cfg = priv->cfg;
	uint32_t rlink = 0;

	rlink = io_read32(priv->remote_desc_base + QMP_EP_LINK_STATE_OFF);
	if (rlink != QMP_LINK_UP)
		return TEE_SUCCESS;  /* Remote not yet ready. */

	io_write32(priv->remote_desc_base + QMP_EP_LINK_STATE_ACK_OFF,
		   QMP_LINK_UP);
	io_write32(priv->local_desc_base + QMP_EP_CH_STATE_OFF,
		   QMP_CH_CONNECTED);
	qmp_signal_remote(cfg);
	priv->state = QMP_STATE_LOCAL_CONNECTING;
	(void)chan;
	return TEE_SUCCESS;
}

static TEE_Result qmp_handle_local_connecting(struct qcom_mbox_chan *chan,
					      struct qcom_mbox_qmp_priv *priv,
					      uint32_t *events)
{
	const struct qcom_mbox_qmp_config *cfg = priv->cfg;
	uint32_t rlink = 0;
	uint32_t rch = 0;

	rlink = io_read32(priv->remote_desc_base + QMP_EP_LINK_STATE_OFF);
	if (rlink != QMP_LINK_UP) {
		*events |= QCOM_MBOX_EVT_REMOTE_RESET;
		qmp_link_teardown(chan, priv, false);
		return TEE_SUCCESS;
	}

	rch = io_read32(priv->remote_desc_base + QMP_EP_CH_STATE_OFF);
	if (rch != QMP_CH_CONNECTED)
		return TEE_SUCCESS;  /* Remote channel not yet connected. */

	io_write32(priv->remote_desc_base + QMP_EP_CH_STATE_ACK_OFF,
		   QMP_CH_CONNECTED);
	qmp_signal_remote(cfg);
	priv->state = QMP_STATE_E2E_CONNECTED;
	*events |= QCOM_MBOX_EVT_CONNECTED;
	(void)chan;
	return TEE_SUCCESS;
}

static TEE_Result qmp_handle_connected(struct qcom_mbox_chan *chan,
				       struct qcom_mbox_qmp_priv *priv,
				       uint32_t *events)
{
	const struct qcom_mbox_qmp_config *cfg = priv->cfg;
	uint32_t rlink = 0;
	uint32_t rch = 0;
	uint32_t msg_len = 0;

	rlink = io_read32(priv->remote_desc_base + QMP_EP_LINK_STATE_OFF);
	rch   = io_read32(priv->remote_desc_base + QMP_EP_CH_STATE_OFF);

	if (rlink != QMP_LINK_UP) {
		*events |= QCOM_MBOX_EVT_REMOTE_RESET |
			   QCOM_MBOX_EVT_DISCONNECTED;
		qmp_link_teardown(chan, priv, true);
		if (rlink != QMP_LINK_DOWN)
			return TEE_ERROR_COMMUNICATION;
		return TEE_SUCCESS;
	}

	if (rch != QMP_CH_CONNECTED) {
		*events |= QCOM_MBOX_EVT_DISCONNECTED;
		io_write32(priv->remote_desc_base + QMP_EP_CH_STATE_ACK_OFF,
			   rch);
		io_write32(priv->local_desc_base + QMP_EP_CH_STATE_OFF,
			   QMP_CH_DISCONNECTED);
		io_write32(priv->local_mbox_base + QMP_MBOX_MSG_LEN_OFF, 0U);
		priv->tx_pending = false;
		chan->mtu = 0U;
		priv->state = QMP_STATE_LINK_NEGOTIATION;
		qmp_signal_remote(cfg);
		if (rch != QMP_CH_DISCONNECTED)
			return TEE_ERROR_COMMUNICATION;
		return TEE_SUCCESS;
	}

	/*
	 * TX_DONE: detect when the remote has consumed the last sent
	 * message by observing the local msg_len field transition from
	 * non-zero to zero.
	 */
	if (priv->tx_pending) {
		if (io_read32(priv->local_mbox_base + QMP_MBOX_MSG_LEN_OFF)
		    == 0U) {
			*events |= QCOM_MBOX_EVT_TX_DONE;
			priv->tx_pending = false;
		}
	}

	msg_len = io_read32(priv->remote_mbox_base + QMP_MBOX_MSG_LEN_OFF);
	if (msg_len > 0U && msg_len <= priv->remote_payload_size)
		*events |= QCOM_MBOX_EVT_RX_READY;

	(void)chan;
	return TEE_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Transport operation callbacks — all return TEE_Result
 * --------------------------------------------------------------------------
 */

static TEE_Result qcom_mbox_qmp_init(struct qcom_mbox_chan *chan)
{
	struct qcom_mbox_qmp_priv *priv = qmp_priv(chan);
	const struct qcom_mbox_qmp_config *cfg = NULL;

	cfg = (const struct qcom_mbox_qmp_config *)chan->cfg->transport_cfg;
	if (!cfg || cfg->desc_base == 0U || cfg->shared_size == 0U || !priv)
		return TEE_ERROR_BAD_PARAMETERS;

	priv->cfg                 = cfg;
	priv->state               = QMP_STATE_LINK_DOWN;
	priv->layout_valid        = false;
	priv->tx_pending          = false;
	priv->local_desc_base     = 0U;
	priv->remote_desc_base    = 0U;
	priv->local_mbox_base     = 0U;
	priv->remote_mbox_base    = 0U;
	priv->local_payload_size  = 0U;
	priv->remote_payload_size = 0U;
	return TEE_SUCCESS;
}

static void qcom_mbox_qmp_deinit(struct qcom_mbox_chan *chan)
{
	struct qcom_mbox_qmp_priv *priv = qmp_priv(chan);
	bool ch_connected = false;

	if (!priv)
		return;
	if (!priv->cfg)
		return;

	if (priv->layout_valid) {
		ch_connected = (priv->state == QMP_STATE_E2E_CONNECTED) ||
			       (priv->state == QMP_STATE_LOCAL_CONNECTING);
		qmp_link_teardown(chan, priv, ch_connected);
	} else {
		qmp_reset_to_link_down(chan, priv);
	}
	priv->cfg = NULL;
}

static TEE_Result qcom_mbox_qmp_process(struct qcom_mbox_chan *chan,
					uint32_t *events)
{
	struct qcom_mbox_qmp_priv *priv = qmp_priv(chan);

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;

	/*
	 * Full system barrier before observing remote state.  Ensures all
	 * previous local writes are visible to the remote and that any
	 * pending load results from previous iterations are committed before
	 * the new observation window begins.
	 */
	dsb();

	switch (priv->state) {
	case QMP_STATE_LINK_DOWN:
		return qmp_handle_link_down(chan, priv);
	case QMP_STATE_LINK_NEGOTIATION:
		return qmp_handle_link_negotiation(chan, priv);
	case QMP_STATE_LOCAL_CONNECTING:
		return qmp_handle_local_connecting(chan, priv, events);
	case QMP_STATE_E2E_CONNECTED:
		return qmp_handle_connected(chan, priv, events);
	default:
		return TEE_ERROR_COMMUNICATION;
	}
}

static TEE_Result qcom_mbox_qmp_send(struct qcom_mbox_chan *chan,
				     const void *buf, size_t len)
{
	struct qcom_mbox_qmp_priv *priv = qmp_priv(chan);

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;
	if (priv->state != QMP_STATE_E2E_CONNECTED)
		return TEE_ERROR_BAD_STATE;
	if (len > (size_t)priv->local_payload_size)
		return TEE_ERROR_EXCESS_DATA;

	/*
	 * The remote clears msg_len after consuming the previous message.
	 * Reject the send if the mailbox is still occupied.
	 */
	if (io_read32(priv->local_mbox_base + QMP_MBOX_MSG_LEN_OFF) != 0U)
		return TEE_ERROR_BUSY;

	qmp_mbox_write(priv->local_mbox_base + QMP_MBOX_MSG_DATA_OFF,
		       buf, len);

	/* Payload must be visible before msg_len is published. */
	dsb();
	io_write32(priv->local_mbox_base + QMP_MBOX_MSG_LEN_OFF,
		   (uint32_t)len);

	priv->tx_pending = true;
	qmp_signal_remote(priv->cfg);

	return TEE_SUCCESS;
}

static TEE_Result qcom_mbox_qmp_recv(struct qcom_mbox_chan *chan,
				     void *buf, size_t *len)
{
	struct qcom_mbox_qmp_priv *priv = qmp_priv(chan);
	uint32_t msg_len = 0;

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;
	if (priv->state != QMP_STATE_E2E_CONNECTED)
		return TEE_ERROR_NO_DATA;

	msg_len = io_read32(priv->remote_mbox_base + QMP_MBOX_MSG_LEN_OFF);
	if (msg_len == 0U)
		return TEE_ERROR_NO_DATA;

	/*
	 * Remote wrote payload before msg_len; observe msg_len before
	 * payload.
	 */
	dsb();

	if (msg_len > priv->remote_payload_size) {
		EMSG("qcom_mbox_qmp: msg_len %u exceeds remote_payload_size %u",
		     msg_len, priv->remote_payload_size);
		return TEE_ERROR_COMMUNICATION;
	}
	if ((size_t)msg_len > *len) {
		/*
		 * Buffer too small.  Preserve the message (do not clear
		 * msg_len) so the caller can retry with a larger buffer.
		 */
		*len = (size_t)msg_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	qmp_mbox_read(buf, priv->remote_mbox_base + QMP_MBOX_MSG_DATA_OFF,
		      (size_t)msg_len);

	/* Complete all payload reads before returning ownership to remote. */
	dsb();
	io_write32(priv->remote_mbox_base + QMP_MBOX_MSG_LEN_OFF, 0U);

	*len = (size_t)msg_len;
	return TEE_SUCCESS;
}

static bool qcom_mbox_qmp_rx_pending(struct qcom_mbox_chan *chan)
{
	struct qcom_mbox_qmp_priv *priv = qmp_priv(chan);
	uint32_t msg_len = 0;

	if (!priv->cfg || priv->state != QMP_STATE_E2E_CONNECTED)
		return false;

	msg_len = io_read32(priv->remote_mbox_base + QMP_MBOX_MSG_LEN_OFF);
	return msg_len > 0U && msg_len <= priv->remote_payload_size;
}

const struct qcom_mbox_ops qcom_mbox_qmp_ops = {
	.init       = qcom_mbox_qmp_init,
	.deinit     = qcom_mbox_qmp_deinit,
	.process    = qcom_mbox_qmp_process,
	.send       = qcom_mbox_qmp_send,
	.recv       = qcom_mbox_qmp_recv,
	.rx_pending = qcom_mbox_qmp_rx_pending,
};
