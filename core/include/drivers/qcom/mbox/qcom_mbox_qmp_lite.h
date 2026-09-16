/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_QMP_LITE_H
#define QCOM_MBOX_QMP_LITE_H

/*
 * QMP-Lite transport — platform-facing types.
 *
 * QMP-Lite is a lightweight register-based mailbox protocol.  Unlike the
 * full QMP transport, there is no shared-memory descriptor discovery phase:
 * the mailbox base addresses and sizes are supplied statically by platform
 * code.  The protocol uses a single 32-bit descriptor register per endpoint
 * for all control signaling.
 *
 * Descriptor bit layout (each endpoint owns one 32-bit register)
 * --------------------------------------------------------------
 * Bit  0  LOCAL_LINK_STATE       - level: 1 = link asserted
 * Bit  1  REMOTE_LINK_STATE_ACK  - level: mirrors remote's LINK_STATE
 * Bit  2  LOCAL_CH_STATE         - level: 1 = channel open
 * Bit  3  REMOTE_CH_STATE_ACK    - level: mirrors remote's CH_STATE
 * Bit  4  LOCAL_TX               - toggle: flipped on each send
 * Bit  5  REMOTE_TX_ACK          - toggle: mirrors remote's TX on receipt
 * Bit  6  LOCAL_RX_DONE          - toggle: flipped after consuming a message
 * Bit  7  REMOTE_RX_DONE_ACK     - toggle: mirrors remote's RX_DONE
 * Bits 16-23  msg_size           - message size in bytes (max 255)
 *
 * Toggle semantics (TX, RX_DONE): sender flips the bit; receiver
 * acknowledges by mirroring the current value into its ack bit.
 *
 * Level semantics (LINK_STATE, CH_STATE): 1 = asserted, 0 = de-asserted.
 *
 * Naming convention
 * -----------------
 * All bit names are from the LOCAL endpoint's perspective.  When reading
 * the REMOTE descriptor register, the same bit positions carry the remote
 * endpoint's corresponding signals.
 *
 * Reconnection model
 * ------------------
 * DISCONNECTED and REMOTE_RESET do not require qcom_mbox_release().
 * The transport automatically re-negotiates.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <types_ext.h>
#include <util.h>

#include <drivers/qcom/mbox/qcom_mbox_qmp.h>

/* Descriptor control bits. */
#define QMP_LITE_LOCAL_LINK_STATE	BIT32(0)
#define QMP_LITE_REMOTE_LINK_STATE_ACK	BIT32(1)
#define QMP_LITE_LOCAL_CH_STATE		BIT32(2)
#define QMP_LITE_REMOTE_CH_STATE_ACK	BIT32(3)
#define QMP_LITE_LOCAL_TX		BIT32(4)
#define QMP_LITE_REMOTE_TX_ACK		BIT32(5)
#define QMP_LITE_LOCAL_RX_DONE		BIT32(6)
#define QMP_LITE_REMOTE_RX_DONE_ACK	BIT32(7)

/* Message size field: bits 16-23 of the descriptor register. */
#define QMP_LITE_MSG_SIZE_SHIFT		16U
#define QMP_LITE_MSG_SIZE_MASK		UINT32_C(0x00FF0000)

/* Maximum message size (8-bit field, max value 255). */
#define QMP_LITE_MAX_MSG_SIZE		255U

/*
 * struct qcom_mbox_qmp_lite_config — static QMP-Lite channel configuration.
 *
 * @local_desc_base:   virtual address of the local descriptor register.
 *                     The local endpoint writes this register.
 * @remote_desc_base:  virtual address of the remote descriptor register.
 *                     The local endpoint reads this register.
 * @local_mbox_size:   size of the local transmit mailbox in bytes.
 *                     Must be > 0 and <= QMP_LITE_MAX_MSG_SIZE.
 * @remote_mbox_size:  size of the remote receive mailbox in bytes.
 *                     Must be > 0 and <= QMP_LITE_MAX_MSG_SIZE.
 * @remote_signal:     register/value pair used to interrupt the remote.
 *                     Set remote_signal.reg = 0 to disable signaling.
 *
 * The local mailbox region immediately follows the local descriptor register
 * in the address map (local_desc_base + sizeof(uint32_t)).  Similarly, the
 * remote mailbox region follows the remote descriptor register.
 */
struct qcom_mbox_qmp_lite_config {
	vaddr_t				local_desc_base;
	vaddr_t				remote_desc_base;
	uint32_t			local_mbox_size;
	uint32_t			remote_mbox_size;
	struct qcom_mbox_signal_config	remote_signal;
};

/*
 * QMP-Lite transport state machine states.
 */
enum qcom_mbox_qmp_lite_state {
	QMP_LITE_STATE_LINK_DOWN = 0,
	QMP_LITE_STATE_LINK_NEGOTIATION,
	QMP_LITE_STATE_LOCAL_CONNECTING,
	QMP_LITE_STATE_E2E_CONNECTED,
};

/*
 * struct qcom_mbox_qmp_lite_priv — QMP-Lite transport runtime state.
 *
 * Platform code must allocate one instance per QMP-Lite channel and pass
 * a pointer via qcom_mbox_chan_config.transport_priv.  All fields are
 * managed by the transport backend; platform code must not access them.
 *
 * @cfg:          back-pointer to the immutable transport configuration.
 * @state:        current state-machine state.
 * @local_desc:   software shadow of the local descriptor register.
 * @remote_desc:  snapshot of the remote descriptor register, refreshed on
 *               each qcom_mbox_process() call.
 * @tx_pending:   true after qcom_mbox_send() until the remote acks the TX
 *               toggle; cleared when QCOM_MBOX_EVT_TX_DONE is generated
 *               or on disconnect.
 */
struct qcom_mbox_qmp_lite_priv {
	const struct qcom_mbox_qmp_lite_config	*cfg;
	enum qcom_mbox_qmp_lite_state		 state;
	uint32_t				 local_desc;
	uint32_t				 remote_desc;
	bool					 tx_pending;
};

/*
 * QMP-Lite transport operations table.
 *
 * Pass &qcom_mbox_qmp_lite_ops as the ops field in qcom_mbox_chan_config
 * to use the QMP-Lite transport backend.
 */
struct qcom_mbox_ops;
extern const struct qcom_mbox_ops qcom_mbox_qmp_lite_ops;

#endif /* QCOM_MBOX_QMP_LITE_H */
