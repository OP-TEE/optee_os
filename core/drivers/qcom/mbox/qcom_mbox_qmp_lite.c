// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Each endpoint owns a 32-bit descriptor register; its mailbox follows at
 * desc_base + 4. A "level" bit is 1 = asserted; a "toggle" bit is flipped by
 * the sender and mirrored by the receiver in its ack bit.
 *
 *   Bit  0  LOCAL_LINK_STATE       - level
 *   Bit  1  REMOTE_LINK_STATE_ACK  - level, mirrors the remote's LINK_STATE
 *   Bit  2  LOCAL_CH_STATE         - level: 1 = channel open
 *   Bit  3  REMOTE_CH_STATE_ACK    - level, mirrors the remote's CH_STATE
 *   Bit  4  LOCAL_TX               - toggle, flipped on each send
 *   Bit  5  REMOTE_TX_ACK          - toggle, mirrors the remote's TX
 *   Bit  6  LOCAL_RX_DONE          - toggle, flipped after consuming a message
 *   Bit  7  REMOTE_RX_DONE_ACK     - toggle, mirrors the remote's RX_DONE
 *   Bits 16-23  msg_size           - message size in bytes (max 255)
 *
 * Bit names are from the owner's point of view: in the remote descriptor the
 * same positions carry the remote's own signals.
 *
 * dsb() orders payload accesses against descriptor updates and the doorbell.
 */

#include <arm.h>
#include <compiler.h>
#include <drivers/qcom/mbox/qcom_mbox.h>
#include <io.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

#include "qcom_mbox_private.h"
#include "qcom_mbox_qmp_lite.h"

#define QMP_LITE_LOCAL_LINK_STATE	BIT32(0)
#define QMP_LITE_REMOTE_LINK_STATE_ACK	BIT32(1)
#define QMP_LITE_LOCAL_CH_STATE		BIT32(2)
#define QMP_LITE_REMOTE_CH_STATE_ACK	BIT32(3)
#define QMP_LITE_LOCAL_TX		BIT32(4)
#define QMP_LITE_REMOTE_TX_ACK		BIT32(5)
#define QMP_LITE_LOCAL_RX_DONE		BIT32(6)
#define QMP_LITE_REMOTE_RX_DONE_ACK	BIT32(7)

#define QMP_LITE_MSG_SIZE_SHIFT		16U
#define QMP_LITE_MSG_SIZE_MASK		UINT32_C(0x00FF0000)

static struct qcom_mbox_qmp_lite_priv *
qmp_lite_priv(struct qcom_mbox_chan *chan)
{
	return (struct qcom_mbox_qmp_lite_priv *)chan->cfg->transport_priv;
}

static __maybe_unused const char *
qmp_lite_state_name(enum qcom_mbox_qmp_lite_state state)
{
	switch (state) {
	case QMP_LITE_STATE_LINK_DOWN:
		return "LINK_DOWN";
	case QMP_LITE_STATE_LINK_NEGOTIATION:
		return "LINK_NEGOTIATION";
	case QMP_LITE_STATE_LOCAL_CONNECTING:
		return "LOCAL_CONNECTING";
	case QMP_LITE_STATE_E2E_CONNECTED:
		return "E2E_CONNECTED";
	default:
		return "UNKNOWN";
	}
}

#define QMP_LITE_DESC_BIT(desc, bit)	(((desc) & (bit)) ? 1 : 0)

/* Each pair is <bit>/<ack>: tx=1/0 = LOCAL_TX set, REMOTE_TX_ACK clear. */
static void qmp_lite_log_desc(const char *owner __maybe_unused,
			      uint32_t desc __maybe_unused)
{
	DMSG("qmp_lite: %s %#010x link=%d/%d ch=%d/%d tx=%d/%d rx_done=%d/%d",
	     owner, desc,
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_LOCAL_LINK_STATE),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_REMOTE_LINK_STATE_ACK),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_LOCAL_CH_STATE),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_REMOTE_CH_STATE_ACK),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_LOCAL_TX),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_REMOTE_TX_ACK),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_LOCAL_RX_DONE),
	     QMP_LITE_DESC_BIT(desc, QMP_LITE_REMOTE_RX_DONE_ACK));
}

/* Only changes are logged: process() is polled in a tight loop. */
static void qmp_lite_update_remote(struct qcom_mbox_qmp_lite_priv *priv)
{
	uint32_t desc = io_read32(priv->cfg->remote_desc_base);

	if (desc != priv->remote_desc)
		qmp_lite_log_desc("remote", desc);
	priv->remote_desc = desc;
}

static void qmp_lite_publish(struct qcom_mbox_qmp_lite_priv *priv)
{
	qmp_lite_log_desc("local", priv->local_desc);
	io_write32(priv->cfg->local_desc_base, priv->local_desc);
}

static void qmp_lite_signal_remote(const struct qcom_mbox_qmp_lite_config *cfg)
{
	dsb();
	if (cfg->remote_signal.reg != 0U)
		io_write32(cfg->remote_signal.reg, cfg->remote_signal.value);
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

static void qmp_lite_link_down(struct qcom_mbox_chan *chan,
			       struct qcom_mbox_qmp_lite_priv *priv)
{
	priv->local_desc = 0U;
	qmp_lite_publish(priv);
	priv->state = QMP_LITE_STATE_LINK_DOWN;
	priv->tx_pending = false;
	priv->resync = false;
	chan->mtu = 0U;
	qmp_lite_signal_remote(priv->cfg);
}

/*
 * The remote de-asserting LINK_STATE means it has reset: drop the link so
 * negotiation restarts. Returns true if it did (never in LINK_DOWN).
 */
static bool qmp_lite_remote_reset(struct qcom_mbox_chan *chan,
				  struct qcom_mbox_qmp_lite_priv *priv,
				  uint32_t *events)
{
	if (priv->state == QMP_LITE_STATE_LINK_DOWN ||
	    (priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) != 0U)
		return false;

	DMSG("qmp_lite: %s -> LINK_DOWN (remote reset)",
	     qmp_lite_state_name(priv->state));
	if (priv->state == QMP_LITE_STATE_E2E_CONNECTED)
		*events |= QCOM_MBOX_EVT_REMOTE_RESET |
			   QCOM_MBOX_EVT_DISCONNECTED;
	qmp_lite_link_down(chan, priv);
	return true;
}

static void qmp_lite_resync_toggles(struct qcom_mbox_qmp_lite_priv *priv)
{
	const uint32_t toggles = QMP_LITE_LOCAL_TX | QMP_LITE_REMOTE_TX_ACK |
				 QMP_LITE_LOCAL_RX_DONE |
				 QMP_LITE_REMOTE_RX_DONE_ACK;
	uint32_t remote = priv->remote_desc;
	uint32_t local = priv->local_desc & ~toggles;

	if ((remote & QMP_LITE_REMOTE_TX_ACK) != 0U)
		local |= QMP_LITE_LOCAL_TX;
	if ((remote & QMP_LITE_REMOTE_RX_DONE_ACK) != 0U)
		local |= QMP_LITE_LOCAL_RX_DONE;
	if ((remote & QMP_LITE_LOCAL_TX) != 0U)
		local |= QMP_LITE_REMOTE_TX_ACK;
	if ((remote & QMP_LITE_LOCAL_RX_DONE) != 0U)
		local |= QMP_LITE_REMOTE_RX_DONE_ACK;

	priv->local_desc = local;
}

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
		if (priv->resync) {
			qmp_lite_resync_toggles(priv);
			priv->resync = false;
		}
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

	if ((priv->remote_desc & QMP_LITE_LOCAL_CH_STATE) == 0U) {
		DMSG("qmp_lite: E2E_CONNECTED -> LOCAL_CONNECTING (ch close)");
		priv->state = QMP_LITE_STATE_LOCAL_CONNECTING;
		priv->tx_pending = false;
		priv->resync = true;
		chan->mtu = 0U;
		qmp_lite_resync_toggles(priv);
		ack_bit(priv, QMP_LITE_LOCAL_CH_STATE,
			QMP_LITE_REMOTE_CH_STATE_ACK);
		*events |= QCOM_MBOX_EVT_DISCONNECTED;
		qmp_lite_publish(priv);
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
}

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
	priv->resync = false;

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

	if (!priv || !priv->cfg)
		return;

	qmp_lite_link_down(chan, priv);
	priv->cfg = NULL;
}

static TEE_Result qcom_mbox_qmp_lite_process(struct qcom_mbox_chan *chan,
					     uint32_t *events)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	const struct qcom_mbox_qmp_lite_config *cfg = NULL;

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;

	/* Order earlier local writes before sampling the remote. */
	dsb();

	cfg = priv->cfg;
	qmp_lite_update_remote(priv);

	if (qmp_lite_remote_reset(chan, priv, events))
		return TEE_SUCCESS;

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
	uint32_t msg_size = 0;

	if (!priv->cfg)
		return TEE_ERROR_GENERIC;
	if (priv->state != QMP_LITE_STATE_E2E_CONNECTED)
		return TEE_ERROR_NO_DATA;

	cfg = priv->cfg;
	qmp_lite_update_remote(priv);

	if (!bit_changed(priv, QMP_LITE_LOCAL_TX, QMP_LITE_REMOTE_TX_ACK))
		return TEE_ERROR_NO_DATA;

	msg_size = (priv->remote_desc & QMP_LITE_MSG_SIZE_MASK) >>
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
