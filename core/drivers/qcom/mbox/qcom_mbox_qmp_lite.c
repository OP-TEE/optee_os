// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QMP-Lite mailbox transport. Each endpoint owns a 32-bit descriptor register;
 * its mailbox follows at desc_base + 4. Bit names are from the owner's point
 * of view: in the remote descriptor the same positions carry the remote's own
 * signals.
 */

#include <arm.h>
#include <compiler.h>
#include <drivers/mailbox_controller.h>
#include <drivers/qcom/mbox/qcom_mbox.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

#include "qcom_mbox_qmp_lite.h"

/*
 * Descriptor bits. Each pair is one of our signals and our copy (_ACK) of the
 * remote's matching signal. A level bit is 1 while asserted; a toggle bit is
 * flipped once per event, and the receiver acknowledges the event by copying
 * the new value into its _ACK bit.
 */
/* Level: link up */
#define QMP_LITE_LOCAL_LINK_STATE	BIT32(0)
#define QMP_LITE_REMOTE_LINK_STATE_ACK	BIT32(1)
/* Level: channel open */
#define QMP_LITE_LOCAL_CH_STATE		BIT32(2)
#define QMP_LITE_REMOTE_CH_STATE_ACK	BIT32(3)
/* Toggle: a message was written to the mailbox */
#define QMP_LITE_LOCAL_TX		BIT32(4)
#define QMP_LITE_REMOTE_TX_ACK		BIT32(5)
/* Toggle: the received message was consumed, the mailbox can be reused */
#define QMP_LITE_LOCAL_RX_DONE		BIT32(6)
#define QMP_LITE_REMOTE_RX_DONE_ACK	BIT32(7)
/* Bits 16-23: size in bytes of the message in the mailbox */
#define QMP_LITE_MSG_SIZE_SHIFT		16U
#define QMP_LITE_MSG_SIZE_MASK		GENMASK_32(23, 16)

/* How long request_channel() waits for the remote to connect */
#define QMP_LITE_CONNECT_TIMEOUT_US	1000000U

static struct qcom_mbox_qmp_lite_priv *
qmp_lite_priv(const struct mbox_chan *chan)
{
	return mbox_controller_get_priv(chan->controller);
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

/*
 * Log a descriptor. Each pair is <bit>/<ack>: tx=1/0 = LOCAL_TX set,
 * REMOTE_TX_ACK clear.
 */
static void qmp_lite_log_desc(const char *owner __maybe_unused,
			      uint32_t desc __maybe_unused)
{
	DMSG("qmp_lite: %s %#010" PRIx32
	     " link=%d/%d ch=%d/%d tx=%d/%d rx_done=%d/%d",
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

/*
 * Read the remote descriptor. Log only when the descriptor changes; this runs
 * on every poll.
 */
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

/* Publish the local descriptor and ring the remote's doorbell */
static void qmp_lite_notify(struct qcom_mbox_qmp_lite_priv *priv)
{
	const struct qcom_mbox_signal_config *sig = &priv->cfg->remote_signal;

	qmp_lite_publish(priv);
	/* Mailbox and descriptor writes must be visible before the doorbell */
	dsb();
	io_write32(sig->reg, sig->value);
}

static void qmp_lite_mbox_write(const struct qcom_mbox_qmp_lite_priv *priv,
				const uint8_t *buf, size_t size)
{
	vaddr_t addr = priv->cfg->local_desc_base + QMP_LITE_DESC_SIZE;

	while (size) {
		uint32_t word = 0;
		size_t chunk = MIN(size, sizeof(word));

		/* 32-bit accesses only; buf may be unaligned */
		memcpy(&word, buf, chunk);
		io_write32(addr, word);
		buf += chunk;
		addr += sizeof(word);
		size -= chunk;
	}
	dsb();
}

static void qmp_lite_mbox_read(const struct qcom_mbox_qmp_lite_priv *priv,
			       uint8_t *buf, size_t size)
{
	vaddr_t addr = priv->cfg->remote_desc_base + QMP_LITE_DESC_SIZE;

	while (size) {
		uint32_t word = io_read32(addr);
		size_t chunk = MIN(size, sizeof(word));

		memcpy(buf, &word, chunk);
		buf += chunk;
		addr += sizeof(word);
		size -= chunk;
	}
	dsb();
}

static bool bit_changed(const struct qcom_mbox_qmp_lite_priv *priv,
			uint32_t remote_bit, uint32_t ack)
{
	return ((priv->remote_desc & remote_bit) != 0U) !=
	       ((priv->local_desc & ack) != 0U);
}

static void ack_bit(struct qcom_mbox_qmp_lite_priv *priv,
		    uint32_t remote_bit, uint32_t ack)
{
	if ((priv->remote_desc & remote_bit) != 0U)
		priv->local_desc |= ack;
	else
		priv->local_desc &= ~ack;
}

static bool ack_if_changed(struct qcom_mbox_qmp_lite_priv *priv,
			   uint32_t remote_bit, uint32_t ack)
{
	if (!bit_changed(priv, remote_bit, ack))
		return false;

	ack_bit(priv, remote_bit, ack);
	return true;
}

static void qmp_lite_link_down(struct qcom_mbox_qmp_lite_priv *priv)
{
	priv->local_desc = 0U;
	priv->state = QMP_LITE_STATE_LINK_DOWN;
	priv->tx_pending = false;
	priv->resync = false;
	qmp_lite_notify(priv);
}

/*
 * A remote that de-asserts LINK_STATE has reset: drop the link so that
 * negotiation restarts. In LINK_DOWN the link is already down. Returns true if
 * the link was dropped.
 */
static bool qmp_lite_remote_reset(struct qcom_mbox_qmp_lite_priv *priv)
{
	if (priv->state == QMP_LITE_STATE_LINK_DOWN ||
	    (priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) != 0U)
		return false;

	DMSG("qmp_lite: %s -> LINK_DOWN (remote reset)",
	     qmp_lite_state_name(priv->state));
	qmp_lite_link_down(priv);
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

static void handle_link_down(struct qcom_mbox_qmp_lite_priv *priv)
{
	if ((priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) != 0U) {
		DMSG("qmp_lite: LINK_DOWN -> LINK_NEGOTIATION");
		priv->local_desc = QMP_LITE_LOCAL_LINK_STATE;
		priv->state = QMP_LITE_STATE_LINK_NEGOTIATION;
		qmp_lite_notify(priv);
	}
}

static void handle_link_negotiation(struct qcom_mbox_qmp_lite_priv *priv)
{
	bool updated = ack_if_changed(priv, QMP_LITE_LOCAL_LINK_STATE,
				      QMP_LITE_REMOTE_LINK_STATE_ACK);

	if ((priv->local_desc & QMP_LITE_REMOTE_LINK_STATE_ACK) != 0U &&
	    (priv->remote_desc & QMP_LITE_LOCAL_LINK_STATE) != 0U) {
		priv->local_desc |= QMP_LITE_LOCAL_CH_STATE;
		DMSG("qmp_lite: LINK_NEGOTIATION -> LOCAL_CONNECTING");
		priv->state = QMP_LITE_STATE_LOCAL_CONNECTING;
		updated = true;
	}
	if (updated)
		qmp_lite_notify(priv);
}

static void handle_local_connecting(struct qcom_mbox_qmp_lite_priv *priv)
{
	bool updated = ack_if_changed(priv, QMP_LITE_LOCAL_CH_STATE,
				      QMP_LITE_REMOTE_CH_STATE_ACK);

	if ((priv->local_desc & QMP_LITE_REMOTE_CH_STATE_ACK) != 0U &&
	    (priv->remote_desc & QMP_LITE_LOCAL_CH_STATE) != 0U) {
		DMSG("qmp_lite: LOCAL_CONNECTING -> E2E_CONNECTED (size=%zu)",
		     priv->cfg->local_mbox_size);
		if (priv->resync) {
			qmp_lite_resync_toggles(priv);
			priv->resync = false;
		}
		priv->state = QMP_LITE_STATE_E2E_CONNECTED;
		updated = true;
	}
	if (updated)
		qmp_lite_notify(priv);
}

static void handle_connected(struct qcom_mbox_qmp_lite_priv *priv)
{
	if ((priv->remote_desc & QMP_LITE_LOCAL_CH_STATE) == 0U) {
		DMSG("qmp_lite: E2E_CONNECTED -> LOCAL_CONNECTING (ch close)");
		priv->state = QMP_LITE_STATE_LOCAL_CONNECTING;
		priv->tx_pending = false;
		priv->resync = true;
		qmp_lite_resync_toggles(priv);
		ack_bit(priv, QMP_LITE_LOCAL_CH_STATE,
			QMP_LITE_REMOTE_CH_STATE_ACK);
		qmp_lite_notify(priv);
		return;
	}

	/* RX_DONE, not TX_ACK, means the remote consumed the message */
	if (ack_if_changed(priv, QMP_LITE_LOCAL_RX_DONE,
			   QMP_LITE_REMOTE_RX_DONE_ACK)) {
		priv->tx_pending = false;
		qmp_lite_notify(priv);
	}
}

/* Run one step of the connection state machine */
static void qmp_lite_process(struct qcom_mbox_qmp_lite_priv *priv)
{
	qmp_lite_update_remote(priv);

	if (qmp_lite_remote_reset(priv))
		return;

	switch (priv->state) {
	case QMP_LITE_STATE_LINK_DOWN:
		handle_link_down(priv);
		break;
	case QMP_LITE_STATE_LINK_NEGOTIATION:
		handle_link_negotiation(priv);
		break;
	case QMP_LITE_STATE_LOCAL_CONNECTING:
		handle_local_connecting(priv);
		break;
	case QMP_LITE_STATE_E2E_CONNECTED:
		handle_connected(priv);
		break;
	default:
		break;
	}
}

static TEE_Result qmp_lite_connect(struct qcom_mbox_qmp_lite_priv *priv)
{
	const struct qcom_mbox_qmp_lite_config *cfg = priv->cfg;
	uint64_t timeout = 0;

	if (!cfg || cfg->local_desc_base == 0U || cfg->remote_desc_base == 0U ||
	    cfg->remote_signal.reg == 0U ||
	    cfg->local_mbox_size == 0U || cfg->remote_mbox_size == 0U ||
	    cfg->local_mbox_size > QMP_LITE_MAX_MSG_SIZE ||
	    cfg->remote_mbox_size > QMP_LITE_MAX_MSG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	priv->state = QMP_LITE_STATE_LINK_DOWN;
	priv->local_desc = 0U;
	priv->remote_desc = 0U;
	priv->tx_pending = false;
	priv->resync = false;

	qmp_lite_publish(priv);
	priv->local_desc = QMP_LITE_LOCAL_LINK_STATE;
	priv->state = QMP_LITE_STATE_LINK_NEGOTIATION;
	qmp_lite_notify(priv);

	timeout = timeout_init_us(QMP_LITE_CONNECT_TIMEOUT_US);
	do {
		qmp_lite_process(priv);
		if (priv->state == QMP_LITE_STATE_E2E_CONNECTED)
			return TEE_SUCCESS;
	} while (!timeout_elapsed(timeout));

	EMSG("qmp_lite: no connection, state %s",
	     qmp_lite_state_name(priv->state));
	qmp_lite_link_down(priv);

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result
qmp_lite_request_channel(struct mbox_controller *controller,
			 const uint32_t *args __unused, size_t args_count,
			 struct mbox_chan **chan)
{
	struct qcom_mbox_qmp_lite_priv *priv =
		mbox_controller_get_priv(controller);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (args_count)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * A channel already granted is reported busy by the framework after
	 * this returns, so its link must be left alone. A request is not
	 * serialised against another one: the single consumer requests the
	 * channel once, at boot.
	 */
	if (!priv->chan.requested) {
		res = qmp_lite_connect(priv);
		if (res)
			return res;
	}

	*chan = &priv->chan;

	return TEE_SUCCESS;
}

static void qmp_lite_free_channel(struct mbox_chan *chan)
{
	qmp_lite_link_down(qmp_lite_priv(chan));
}

static TEE_Result qmp_lite_send_sync(const struct mbox_chan *chan, void *req)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	struct qcom_mbox_msg *msg = req;

	if (!msg->buf || !msg->len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (msg->len > priv->cfg->local_mbox_size)
		return TEE_ERROR_EXCESS_DATA;

	qmp_lite_process(priv);

	if (priv->state != QMP_LITE_STATE_E2E_CONNECTED)
		return TEE_ERROR_BAD_STATE;
	if (priv->tx_pending)
		return TEE_ERROR_BUSY;

	qmp_lite_mbox_write(priv, msg->buf, msg->len);

	priv->local_desc &= ~QMP_LITE_MSG_SIZE_MASK;
	priv->local_desc |= (msg->len << QMP_LITE_MSG_SIZE_SHIFT) &
			    QMP_LITE_MSG_SIZE_MASK;
	priv->local_desc ^= QMP_LITE_LOCAL_TX;
	priv->tx_pending = true;
	qmp_lite_notify(priv);

	return TEE_SUCCESS;
}

static TEE_Result qmp_lite_recv_sync(const struct mbox_chan *chan, void *req)
{
	struct qcom_mbox_qmp_lite_priv *priv = qmp_lite_priv(chan);
	struct qcom_mbox_msg *msg = req;
	size_t msg_size = 0;

	if (!msg->buf)
		return TEE_ERROR_BAD_PARAMETERS;

	qmp_lite_process(priv);

	if (priv->state != QMP_LITE_STATE_E2E_CONNECTED)
		return TEE_ERROR_BAD_STATE;
	if (!bit_changed(priv, QMP_LITE_LOCAL_TX, QMP_LITE_REMOTE_TX_ACK))
		return TEE_ERROR_NO_DATA;

	msg_size = (priv->remote_desc & QMP_LITE_MSG_SIZE_MASK) >>
		   QMP_LITE_MSG_SIZE_SHIFT;

	if (msg_size == 0U || msg_size > priv->cfg->remote_mbox_size) {
		EMSG("qcom_mbox_qmp_lite: bad msg_size %zu", msg_size);
		return TEE_ERROR_COMMUNICATION;
	}
	if (msg_size > msg->len) {
		msg->len = msg_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	qmp_lite_mbox_read(priv, msg->buf, msg_size);
	msg->len = msg_size;

	ack_bit(priv, QMP_LITE_LOCAL_TX, QMP_LITE_REMOTE_TX_ACK);
	priv->local_desc ^= QMP_LITE_LOCAL_RX_DONE;
	qmp_lite_notify(priv);

	return TEE_SUCCESS;
}

const struct mbox_controller_ops qcom_mbox_qmp_lite_ops = {
	.request_channel = qmp_lite_request_channel,
	.free_channel = qmp_lite_free_channel,
	.send_sync = qmp_lite_send_sync,
	.recv_sync = qmp_lite_recv_sync,
};
