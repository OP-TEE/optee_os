// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QMP-Lite transport backend.
 *
 * QMP-Lite is a lightweight register-based mailbox protocol.  All descriptor
 * and mailbox fields are device MMIO registers; io_read32/io_write32 are
 * used for all accesses.  Payload bytes are packed/unpacked in local
 * variables (little-endian, 32-bit aligned).
 *
 * Protocol summary
 * ----------------
 * Each endpoint owns one 32-bit descriptor register.  The bit layout is
 * described in include/drivers/qcom/mbox/qcom_mbox_qmp_lite.h.
 *
 * The local mailbox region immediately follows the local descriptor register
 * (local_desc_base + 4).  The remote mailbox region immediately follows the
 * remote descriptor register (remote_desc_base + 4).
 *
 * Non-blocking design
 * -------------------
 *   send()    - writes the message and toggles LOCAL_TX; returns immediately.
 *               QCOM_MBOX_EVT_TX_DONE is set by process() when the remote
 *               mirrors LOCAL_TX into REMOTE_TX_ACK.
 *   recv()    - reads the message when available; returns TEE_ERROR_NO_DATA
 *               otherwise.  After reading, toggles LOCAL_RX_DONE to signal
 *               the remote.
 *   process() - dispatches to per-state handlers that advance the state
 *               machine and set events.
 *
 * Memory ordering
 * ---------------
 * dsb() is used throughout to enforce ordering between shared-memory writes
 * and the doorbell signal, and between the TX toggle observation and payload
 * reads.  dsb() is a superset of the TF-A dmbst()/dmbld()/dmbsy() barriers
 * used in the original code.
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
#include <drivers/qcom/mbox/qcom_mbox_qmp_lite.h>
#include "qcom_mbox_private.h"

/* --------------------------------------------------------------------------
 * Low-level helpers
 * --------------------------------------------------------------------------
 */

static struct qcom_mbox_qmp_lite_priv *
qmp_lite_priv(struct qcom_mbox_chan *chan)
{
	return (struct qcom_mbox_qmp_lite_priv *)chan->cfg->transport_priv;
}

static uint32_t qmp_lite_read_remote(const struct qcom_mbox_qmp_lite_priv *priv)
{
	return io_read32(priv->cfg->remote_desc_base);
}

static void qmp_lite_publish(struct qcom_mbox_qmp_lite_priv *priv)
{
	io_write32(priv->cfg->local_desc_base, priv->local_desc);
}

static void qmp_lite_signal_remote(const struct qcom_mbox_qmp_lite_config *cfg)
{
	dsb();
	if (cfg->remote_signal.reg != 0U) {
		io_setbits32(cfg->remote_signal.reg, cfg->remote_signal.value);
		io_clrbits32(cfg->remote_signal.reg, cfg->remote_signal.value);
	}
}

static void qmp_lite_mbox_write(const struct qcom_mbox_qmp_lite_priv *priv,
				const uint8_t *buf, uint32_t size)
{
	vaddr_t addr = priv->cfg->local_desc_base + sizeof(uint32_t);
	uint32_t full = size >> 2U;
	uint32_t rem  = size & 3U;
	uint32_t word = 0;
	uint32_t i = 0;

	for (i = 0U; i < full; i++) {
		memcpy(&word, buf, sizeof(word));
		io_write32(addr, word);
		buf  += sizeof(uint32_t);
		addr += sizeof(uint32_t);
	}
	if (rem != 0U) {
		word = 0U;
		memcpy(&word, buf, rem);
		io_write32(addr, word);
	}
	dsb();
}

static void qmp_lite_mbox_read(const struct qcom_mbox_qmp_lite_priv *priv,
			       uint8_t *buf, uint32_t size)
{
	vaddr_t addr = priv->cfg->remote_desc_base + sizeof(uint32_t);
	uint32_t full = size >> 2U;
	uint32_t rem  = size & 3U;
	uint32_t word = 0;
	uint32_t i = 0;

	dsb();
	for (i = 0U; i < full; i++) {
		word = io_read32(addr);
		memcpy(buf, &word, sizeof(word));
		buf  += sizeof(uint32_t);
		addr += sizeof(uint32_t);
	}
	if (rem != 0U) {
		word = io_read32(addr);
		memcpy(buf, &word, rem);
	}
}

static bool bit_changed(const struct qcom_mbox_qmp_lite_priv *priv,
			uint32_t remote_bit, uint32_t ack_bit)
{
	return ((priv->remote_desc & remote_bit) != 0U) !=
	       ((priv->local_desc  & ack_bit)    != 0U);
}

static void ack_bit(struct qcom_mbox_qmp_lite_priv *priv,
		    uint32_t remote_bit, uint32_t ack)
{
	if ((priv->remote_desc & remote_bit) != 0U)
		priv->local_desc |= ack;
	else
		priv->local_desc &= ~ack;
}

static bool tx_acked(const struct qcom_mbox_qmp_lite_priv *priv)
{
	return ((priv->local_desc  & QMP_LITE_LOCAL_TX)      != 0U) ==
	       ((priv->remote_desc & QMP_LITE_REMOTE_TX_ACK) != 0U);
}

/* --------------------------------------------------------------------------
 * Per-state process handlers
 * --------------------------------------------------------------------------
 */

static void handle_link_down(struct qcom_mbox_qmp_lite_priv *priv,
			     const struct qcom_mbox_qmp_lite_config *cfg)
{
	if ((priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) != 0U) {
		priv->local_desc = QMP_LITE_LOCAL_LINK_STATE;
		qmp_lite_publish(priv);
		DMSG("qmp_lite: LINK_DOWN -> LINK_NEGOTIATION");
		priv->state = QMP_LITE_STATE_LINK_NEGOTIATION;
		qmp_lite_signal_remote(cfg);
	}
}

static void handle_link_negotiation(struct qcom_mbox_qmp_lite_priv *priv,
				    const struct qcom_mbox_qmp_lite_config *cfg)
{
	bool updated = false;

	if ((priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) == 0U) {
		priv->local_desc = 0U;
		qmp_lite_publish(priv);
		DMSG("qmp_lite: LINK_NEGOTIATION -> LINK_DOWN (remote reset)");
		priv->state = QMP_LITE_STATE_LINK_DOWN;
		qmp_lite_signal_remote(cfg);
		return;
	}
	if (bit_changed(priv, QMP_LITE_LOCAL_LINK_STATE,
			QMP_LITE_REMOTE_LINK_STATE_ACK)) {
		ack_bit(priv, QMP_LITE_LOCAL_LINK_STATE,
			QMP_LITE_REMOTE_LINK_STATE_ACK);
		updated = true;
	}
	if ((priv->local_desc & QMP_LITE_REMOTE_LINK_STATE_ACK) != 0U &&
	    (priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) != 0U) {
		priv->local_desc |= QMP_LITE_LOCAL_CH_STATE;
		DMSG("qmp_lite: LINK_NEGOTIATION -> LOCAL_CONNECTING");
		priv->state = QMP_LITE_STATE_LOCAL_CONNECTING;
		updated = true;
	}
	if (updated) {
		qmp_lite_publish(priv);
		qmp_lite_signal_remote(cfg);
	}
}

static void handle_local_connecting(struct qcom_mbox_chan *chan,
				    struct qcom_mbox_qmp_lite_priv *priv,
				    const struct qcom_mbox_qmp_lite_config *cfg,
				    uint32_t *events)
{
	bool updated = false;

	if ((priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) == 0U) {
		priv->local_desc = 0U;
		qmp_lite_publish(priv);
		DMSG("qmp_lite: LOCAL_CONNECTING -> LINK_DOWN (remote reset)");
		priv->state = QMP_LITE_STATE_LINK_DOWN;
		priv->tx_pending = false;
		chan->mtu = 0U;
		qmp_lite_signal_remote(cfg);
		return;
	}
	if (bit_changed(priv, QMP_LITE_LOCAL_CH_STATE,
			QMP_LITE_REMOTE_CH_STATE_ACK)) {
		ack_bit(priv, QMP_LITE_LOCAL_CH_STATE,
			QMP_LITE_REMOTE_CH_STATE_ACK);
		updated = true;
	}
	if ((priv->local_desc & QMP_LITE_REMOTE_CH_STATE_ACK) != 0U &&
	    (priv->remote_desc & QMP_LITE_LOCAL_CH_STATE) != 0U) {
		DMSG("qmp_lite: LOCAL_CONNECTING -> E2E_CONNECTED (mtu=%zu)",
		     (size_t)cfg->local_mbox_size);
		priv->state = QMP_LITE_STATE_E2E_CONNECTED;
		chan->mtu = (size_t)cfg->local_mbox_size;
		*events |= QCOM_MBOX_EVT_CONNECTED;
		updated = true;
	}
	if (updated) {
		qmp_lite_publish(priv);
		qmp_lite_signal_remote(cfg);
	}
}

static void handle_connected(struct qcom_mbox_chan *chan,
			     struct qcom_mbox_qmp_lite_priv *priv,
			     const struct qcom_mbox_qmp_lite_config *cfg,
			     uint32_t *events)
{
	bool updated = false;

	if ((priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) == 0U) {
		priv->local_desc = 0U;
		qmp_lite_publish(priv);
		DMSG("qmp_lite: E2E_CONNECTED -> LINK_DOWN (remote reset)");
		priv->state = QMP_LITE_STATE_LINK_DOWN;
		priv->tx_pending = false;
		chan->mtu = 0U;
		*events |= QCOM_MBOX_EVT_REMOTE_RESET |
			   QCOM_MBOX_EVT_DISCONNECTED;
		qmp_lite_signal_remote(cfg);
		return;
	}

	if (priv->tx_pending && tx_acked(priv)) {
		priv->tx_pending = false;
		DMSG("qmp_lite: TX_DONE on '%s'", chan->cfg->name);
		*events |= QCOM_MBOX_EVT_TX_DONE;
	}

	if (bit_changed(priv, QMP_LITE_LOCAL_RX_DONE,
			QMP_LITE_REMOTE_RX_DONE_ACK)) {
		ack_bit(priv, QMP_LITE_LOCAL_RX_DONE,
			QMP_LITE_REMOTE_RX_DONE_ACK);
		updated = true;
	}

	if (bit_changed(priv, QMP_LITE_LOCAL_TX, QMP_LITE_REMOTE_TX_ACK)) {
		DMSG("qmp_lite: RX_READY on '%s'", chan->cfg->name);
		*events |= QCOM_MBOX_EVT_RX_READY;
	}

	if (updated) {
		qmp_lite_publish(priv);
		qmp_lite_signal_remote(cfg);
	}

	(void)chan;
}

/* --------------------------------------------------------------------------
 * Transport operation callbacks — all return TEE_Result
 * --------------------------------------------------------------------------
 */

static TEE_Result qcom_mbox_qmp_lite_init(struct qcom_mbox_chan *chan)
{
	struct qcom_mbox_qmp_lite_priv *priv = NULL;
	const struct qcom_mbox_qmp_lite_config *cfg = NULL;

	priv = qmp_lite_priv(chan);
	cfg = (const struct qcom_mbox_qmp_lite_config *)
		chan->cfg->transport_cfg;
	if (!cfg || !priv ||
	    cfg->local_desc_base == 0U || cfg->remote_desc_base == 0U)
		return TEE_ERROR_BAD_PARAMETERS;
	if (cfg->local_mbox_size == 0U ||
	    cfg->remote_mbox_size == 0U ||
	    cfg->local_mbox_size > QMP_LITE_MAX_MSG_SIZE ||
	    cfg->remote_mbox_size > QMP_LITE_MAX_MSG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	priv->cfg = cfg;
	priv->state = QMP_LITE_STATE_LINK_DOWN;
	priv->local_desc = 0U;
	priv->remote_desc = 0U;
	priv->tx_pending = false;

	qmp_lite_publish(priv);
	dsb();
	priv->local_desc = QMP_LITE_LOCAL_LINK_STATE;
	qmp_lite_publish(priv);
	priv->state = QMP_LITE_STATE_LINK_NEGOTIATION;
	qmp_lite_signal_remote(cfg);

	return TEE_SUCCESS;
}

static void qcom_mbox_qmp_lite_deinit(struct qcom_mbox_chan *chan)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	const struct qcom_mbox_qmp_lite_config *cfg = NULL;

	if (!priv)
		return;
	if (!priv->cfg)
		return;
	cfg = priv->cfg;

	priv->local_desc = 0U;
	qmp_lite_publish(priv);
	priv->state = QMP_LITE_STATE_LINK_DOWN;
	priv->tx_pending = false;
	chan->mtu = 0U;
	qmp_lite_signal_remote(cfg);

	priv->cfg = NULL;
}

static TEE_Result qcom_mbox_qmp_lite_process(struct qcom_mbox_chan *chan,
					     uint32_t *events)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	const struct qcom_mbox_qmp_lite_config *cfg = NULL;

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;

	/*
	 * Full system barrier before observing remote state.  Ensures all
	 * previous local writes are visible to the remote and any pending
	 * load results are committed before the new observation window.
	 */
	dsb();

	cfg = priv->cfg;
	priv->remote_desc = qmp_lite_read_remote(priv);

	switch (priv->state) {
	case QMP_LITE_STATE_LINK_DOWN:
		handle_link_down(priv, cfg);
		break;
	case QMP_LITE_STATE_LINK_NEGOTIATION:
		handle_link_negotiation(priv, cfg);
		break;
	case QMP_LITE_STATE_LOCAL_CONNECTING:
		handle_local_connecting(chan, priv, cfg, events);
		break;
	case QMP_LITE_STATE_E2E_CONNECTED:
		handle_connected(chan, priv, cfg, events);
		break;
	default:
		return TEE_ERROR_COMMUNICATION;
	}

	return TEE_SUCCESS;
}

static TEE_Result qcom_mbox_qmp_lite_send(struct qcom_mbox_chan *chan,
					  const void *buf, size_t len)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	const struct qcom_mbox_qmp_lite_config *cfg = NULL;

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;
	if (priv->state != QMP_LITE_STATE_E2E_CONNECTED)
		return TEE_ERROR_BAD_STATE;
	if (priv->tx_pending)
		return TEE_ERROR_BUSY;
	if (len > (size_t)priv->cfg->local_mbox_size)
		return TEE_ERROR_EXCESS_DATA;

	cfg = priv->cfg;

	qmp_lite_mbox_write(priv, (const uint8_t *)buf, (uint32_t)len);

	priv->local_desc &= ~QMP_LITE_MSG_SIZE_MASK;
	priv->local_desc |= ((uint32_t)len << QMP_LITE_MSG_SIZE_SHIFT)
			    & QMP_LITE_MSG_SIZE_MASK;
	priv->local_desc ^= QMP_LITE_LOCAL_TX;
	qmp_lite_publish(priv);

	priv->tx_pending = true;
	qmp_lite_signal_remote(cfg);

	return TEE_SUCCESS;
}

static TEE_Result qcom_mbox_qmp_lite_recv(struct qcom_mbox_chan *chan,
					  void *buf, size_t *len)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	const struct qcom_mbox_qmp_lite_config *cfg = NULL;
	uint32_t remote_desc = 0;
	uint32_t msg_size = 0;

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;
	if (priv->state != QMP_LITE_STATE_E2E_CONNECTED)
		return TEE_ERROR_NO_DATA;

	cfg = priv->cfg;
	remote_desc = qmp_lite_read_remote(priv);
	priv->remote_desc = remote_desc;

	if (!bit_changed(priv, QMP_LITE_LOCAL_TX, QMP_LITE_REMOTE_TX_ACK))
		return TEE_ERROR_NO_DATA;

	msg_size = (remote_desc & QMP_LITE_MSG_SIZE_MASK) >>
		   QMP_LITE_MSG_SIZE_SHIFT;

	if (msg_size == 0U || msg_size > cfg->remote_mbox_size) {
		EMSG("qcom_mbox_qmp_lite: bad msg_size %u", msg_size);
		return TEE_ERROR_COMMUNICATION;
	}
	if ((size_t)msg_size > *len) {
		*len = (size_t)msg_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	qmp_lite_mbox_read(priv, (uint8_t *)buf, msg_size);
	*len = (size_t)msg_size;

	dsb();
	ack_bit(priv, QMP_LITE_LOCAL_TX, QMP_LITE_REMOTE_TX_ACK);
	priv->local_desc ^= QMP_LITE_LOCAL_RX_DONE;
	qmp_lite_publish(priv);
	qmp_lite_signal_remote(cfg);

	(void)chan;
	return TEE_SUCCESS;
}

static bool qcom_mbox_qmp_lite_rx_pending(struct qcom_mbox_chan *chan)
{
	const struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	uint32_t remote_desc = 0;

	if (!priv->cfg ||
	    priv->state != QMP_LITE_STATE_E2E_CONNECTED)
		return false;
	remote_desc = io_read32(priv->cfg->remote_desc_base);
	return ((remote_desc & QMP_LITE_LOCAL_TX) != 0U) !=
	       ((priv->local_desc & QMP_LITE_REMOTE_TX_ACK) != 0U);
}

const struct qcom_mbox_ops qcom_mbox_qmp_lite_ops = {
	.init       = qcom_mbox_qmp_lite_init,
	.deinit     = qcom_mbox_qmp_lite_deinit,
	.process    = qcom_mbox_qmp_lite_process,
	.send       = qcom_mbox_qmp_lite_send,
	.recv       = qcom_mbox_qmp_lite_recv,
	.rx_pending = qcom_mbox_qmp_lite_rx_pending,
};
