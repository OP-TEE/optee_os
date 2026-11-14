/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_QMP_LITE_H
#define QCOM_MBOX_QMP_LITE_H

/*
 * The descriptor bit layout is in qcom_mbox_qmp_lite.c.
 *
 * DISCONNECTED is also reported when the remote closes the channel while the
 * link stays up; the channel connects again once the remote reopens it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types_ext.h>

#include "qcom_mbox_private.h"

/* The size field in the descriptor is 8 bits wide. */
#define QMP_LITE_MAX_MSG_SIZE		255U

/* Doorbell bit in the remote-signal register (APCS_*_TZ_IPC_INTERRUPT). */
#define TME_QMP_LITE_IRQ_OUT_BIT_MASK	0x00200000U

/*
 * @local_desc_base:   we write this descriptor.
 * @remote_desc_base:  we only read this descriptor.
 * @local_mbox_size:   size in bytes of the mailbox we transmit to; becomes the
 *                     channel MTU. Must be > 0 and <= QMP_LITE_MAX_MSG_SIZE.
 * @remote_mbox_size:  size in bytes of the mailbox we receive from (the
 *                     remote's transmit mailbox). Must be > 0 and
 *                     <= QMP_LITE_MAX_MSG_SIZE.
 */
struct qcom_mbox_qmp_lite_config {
	vaddr_t				local_desc_base;
	vaddr_t				remote_desc_base;
	uint32_t			local_mbox_size;
	uint32_t			remote_mbox_size;
	struct qcom_mbox_signal_config	remote_signal;
};

enum qcom_mbox_qmp_lite_state {
	QMP_LITE_STATE_LINK_DOWN = 0,
	QMP_LITE_STATE_LINK_NEGOTIATION,
	QMP_LITE_STATE_LOCAL_CONNECTING,
	QMP_LITE_STATE_E2E_CONNECTED,
};

/*
 * The SoC code allocates one per channel and passes it as transport_priv.
 *
 * @local_desc:  software shadow of the local descriptor register.
 * @remote_desc: snapshot of the remote descriptor register.
 * @tx_pending:  a sent message is not yet acknowledged; cleared when TX_DONE
 *               is raised or on disconnect.
 * @resync:      the remote closed the channel; the toggle bits are realigned
 *               again when it reopens.
 */
struct qcom_mbox_qmp_lite_priv {
	const struct qcom_mbox_qmp_lite_config	*cfg;
	enum qcom_mbox_qmp_lite_state		 state;
	uint32_t				 local_desc;
	uint32_t				 remote_desc;
	bool					 tx_pending;
	bool					 resync;
};

extern const struct qcom_mbox_ops qcom_mbox_qmp_lite_ops;

#endif /* QCOM_MBOX_QMP_LITE_H */
