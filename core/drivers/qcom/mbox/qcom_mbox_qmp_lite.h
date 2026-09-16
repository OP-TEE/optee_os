/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_QMP_LITE_H
#define QCOM_MBOX_QMP_LITE_H

/*
 * QMP-Lite transport — types shared with the per-SoC channel table.
 *
 * QMP-Lite is a lightweight register-based mailbox protocol.  There is no
 * shared-memory descriptor discovery phase: the mailbox base addresses and
 * sizes are supplied statically by the SoC code.  The protocol uses a single
 * 32-bit descriptor register per endpoint for all control signaling; its bit
 * layout is documented in qcom_mbox_qmp_lite.c.
 *
 * DISCONNECTED and REMOTE_RESET do not require qcom_mbox_release().
 * The transport automatically re-negotiates.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <types_ext.h>

#include "qcom_mbox_private.h"

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
 * The SoC code must allocate one instance per QMP-Lite channel and pass
 * a pointer via qcom_mbox_chan_config.transport_priv.  All fields are
 * managed by the transport backend and must not be accessed elsewhere.
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
extern const struct qcom_mbox_ops qcom_mbox_qmp_lite_ops;

#endif /* QCOM_MBOX_QMP_LITE_H */
