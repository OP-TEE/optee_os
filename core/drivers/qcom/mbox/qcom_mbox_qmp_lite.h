/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_QMP_LITE_H
#define QCOM_MBOX_QMP_LITE_H

/*
 * QMP-Lite mailbox transport. The descriptor bit layout is in
 * qcom_mbox_qmp_lite.c.
 *
 * The remote closing the channel while the link stays up takes the channel
 * back to the connecting state; it is connected again once the remote reopens
 * it.
 */

#include <drivers/mailbox_controller.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types_ext.h>

/* The descriptor register at the start of each mailbox */
#define QMP_LITE_DESC_SIZE		sizeof(uint32_t)

/* The size field in the descriptor is 8 bits wide. */
#define QMP_LITE_MAX_MSG_SIZE		255U

/*
 * struct qcom_mbox_signal_config - Doorbell used to notify the remote
 * @reg:   register to write
 * @value: value written to @reg
 */
struct qcom_mbox_signal_config {
	vaddr_t reg;
	uint32_t value;
};

/*
 * struct qcom_mbox_qmp_lite_config - Static configuration of a QMP-Lite link
 * @local_desc_base:  descriptor register we write
 * @remote_desc_base: descriptor register we only read
 * @local_mbox_size:  size in bytes of the mailbox we transmit to; the largest
 *                    message we can send. Must be > 0 and
 *                    <= QMP_LITE_MAX_MSG_SIZE.
 * @remote_mbox_size: size in bytes of the mailbox we receive from (the
 *                    remote's transmit mailbox). Must be > 0 and
 *                    <= QMP_LITE_MAX_MSG_SIZE.
 * @remote_signal:    doorbell that tells the remote the descriptor changed
 */
struct qcom_mbox_qmp_lite_config {
	vaddr_t local_desc_base;
	vaddr_t remote_desc_base;
	size_t local_mbox_size;
	size_t remote_mbox_size;
	struct qcom_mbox_signal_config remote_signal;
};

/* Connection steps, in the order a channel goes through them */
enum qcom_mbox_qmp_lite_state {
	QMP_LITE_STATE_LINK_DOWN = 0,
	QMP_LITE_STATE_LINK_NEGOTIATION,
	QMP_LITE_STATE_LOCAL_CONNECTING,
	QMP_LITE_STATE_E2E_CONNECTED,
};

/*
 * struct qcom_mbox_qmp_lite_priv - Run-time state of a QMP-Lite link
 * @chan:        the one channel of the link, given to the consumer
 * @cfg:         configuration, set by the SoC code before the controller is
 *               registered
 * @state:       connection state
 * @local_desc:  software shadow of the local descriptor register
 * @remote_desc: snapshot of the remote descriptor register
 * @tx_pending:  a sent message is not yet consumed by the remote; cleared when
 *               the remote flips RX_DONE or on disconnect
 * @resync:      the remote closed the channel; the toggle bits are realigned
 *               again when it reopens
 *
 * The SoC code allocates one per link and gives it to the controller
 * descriptor as priv.
 */
struct qcom_mbox_qmp_lite_priv {
	struct mbox_chan chan;
	const struct qcom_mbox_qmp_lite_config *cfg;
	enum qcom_mbox_qmp_lite_state state;
	uint32_t local_desc;
	uint32_t remote_desc;
	bool tx_pending;
	bool resync;
};

extern const struct mbox_controller_ops qcom_mbox_qmp_lite_ops;

#endif /* QCOM_MBOX_QMP_LITE_H */
