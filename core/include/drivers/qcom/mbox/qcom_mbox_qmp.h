/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_QMP_H
#define QCOM_MBOX_QMP_H

/*
 * QMP (Qualcomm Message Protocol) transport — platform-facing types.
 *
 * Platform code includes this header to define static QMP channel
 * configurations and allocate per-channel runtime state.
 *
 * Protocol overview
 * -----------------
 * QMP uses a shared-memory descriptor region to negotiate link and channel
 * state between two endpoints:
 *
 *   Local endpoint:  SCORE (macro/slave)  — this firmware (S-EL1)
 *   Remote endpoint: MCORE (micro/master) — the remote processor (e.g. TME)
 *
 * The remote master initialises the shared descriptor and mailbox layout
 * asynchronously.  init() always succeeds; process() discovers the layout
 * when the initialisation signature (QMP_MAGIC) is first observed.
 *
 * State machine
 * -------------
 *   LINK_DOWN        — waiting for the remote master to publish QMP_MAGIC.
 *   LINK_NEGOTIATION — local link is UP; waiting for remote link ack.
 *   LOCAL_CONNECTING — local channel is CONNECTED; waiting for remote ack.
 *   E2E_CONNECTED    — both endpoints connected; data transfer is possible.
 *
 * MTU
 * ---
 * The effective TX MTU equals local_payload_size, which is valid only after
 * layout discovery (state >= LINK_NEGOTIATION).  qcom_mbox_get_mtu() returns
 * TEE_ERROR_NO_DATA before the MTU is valid.
 *
 * Trust model
 * -----------
 * The remote endpoint is a trusted subsystem.  All remote-supplied layout
 * parameters (mailbox offsets and sizes) are validated by qmp_validate_layout()
 * before use.  Platform-supplied addresses (desc_base, remote_signal.reg) are
 * assumed to be correct virtual addresses; no runtime range validation is
 * performed on them.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <types_ext.h>

/*
 * struct qcom_mbox_signal_config — MMIO doorbell descriptor.
 *
 * @reg:   virtual address of the interrupt-set register.
 *         Set to 0 to disable signaling (polling-only mode).
 * @value: value to write to @reg when signaling the remote.
 */
struct qcom_mbox_signal_config {
	vaddr_t		reg;
	uint32_t	value;
};

/*
 * struct qcom_mbox_qmp_config — static QMP channel configuration.
 *
 * @desc_base:     virtual base address of the shared QMP descriptor and
 *                 mailbox region.  Must be non-zero.
 * @shared_size:   total size of the shared region in bytes.  Must be at
 *                 least QMP_DESC_HEADER_SIZE (188 bytes).
 * @remote_signal: register/value pair used to interrupt the remote endpoint.
 *                 Set remote_signal.reg = 0 to disable signaling.
 */
struct qcom_mbox_qmp_config {
	vaddr_t				desc_base;
	uint32_t			shared_size;
	struct qcom_mbox_signal_config	remote_signal;
};

/*
 * QMP transport state machine states.
 *
 * Exposed here so that platform code can allocate struct qcom_mbox_qmp_priv
 * statically.  Platform code must not read or write the state field directly.
 */
enum qcom_mbox_qmp_state {
	QMP_STATE_LINK_DOWN = 0,
	QMP_STATE_LINK_NEGOTIATION,
	QMP_STATE_LOCAL_CONNECTING,
	QMP_STATE_E2E_CONNECTED,
};

/*
 * struct qcom_mbox_qmp_priv — QMP transport runtime state.
 *
 * Platform code must allocate one instance per QMP channel and pass a
 * pointer via qcom_mbox_chan_config.transport_priv.  All fields are managed
 * by the transport backend; platform code must not access them directly.
 *
 * @cfg:                  back-pointer to the immutable transport config.
 * @state:                current state-machine state.
 * @layout_valid:         set after the shared descriptor layout is validated.
 * @tx_pending:           true after qcom_mbox_send() until the remote clears
 *                        msg_len; cleared when QCOM_MBOX_EVT_TX_DONE is
 *                        generated or on disconnect.
 * @local_desc_base:      virtual base of the local (SCORE) endpoint descriptor.
 * @remote_desc_base:     virtual base of the remote (MCORE) endpoint
 *                        descriptor.
 * @local_mbox_base:      virtual base of the local transmit mailbox.
 * @remote_mbox_base:     virtual base of the remote receive mailbox.
 * @local_payload_size:   usable TX capacity in bytes.
 * @remote_payload_size:  usable RX capacity in bytes.
 */
struct qcom_mbox_qmp_priv {
	const struct qcom_mbox_qmp_config	*cfg;
	enum qcom_mbox_qmp_state		 state;
	bool					 layout_valid;
	bool					 tx_pending;
	vaddr_t					 local_desc_base;
	vaddr_t					 remote_desc_base;
	vaddr_t					 local_mbox_base;
	vaddr_t					 remote_mbox_base;
	uint32_t				 local_payload_size;
	uint32_t				 remote_payload_size;
};

/*
 * QMP transport operations table.
 *
 * Pass &qcom_mbox_qmp_ops as the ops field in qcom_mbox_chan_config to use
 * the QMP transport backend.
 */
struct qcom_mbox_ops;
extern const struct qcom_mbox_ops qcom_mbox_qmp_ops;

#endif /* QCOM_MBOX_QMP_H */
