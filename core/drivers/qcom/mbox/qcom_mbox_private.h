/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_PRIVATE_H
#define QCOM_MBOX_PRIVATE_H

/*
 * Driver-internal header for the Qualcomm mailbox framework.
 *
 * Included only by the framework core (qcom_mbox.c) and transport backends
 * (qcom_mbox_qmp.c, qcom_mbox_qmp_lite.c).  Platform code must not include
 * this header directly.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tee_api_types.h>

#include <drivers/qcom/mbox/qcom_mbox_types.h>

/*
 * struct qcom_mbox_ops — transport operations table.
 *
 * Every transport backend must populate all function pointers; NULL entries
 * are rejected by config_validate() in qcom_mbox.c.
 *
 * init:       one-time channel setup; called by qcom_mbox_request().
 *             Returns TEE_SUCCESS on success, TEE_ERROR_* on failure.
 *             deinit() will be called to clean up any partial initialisation.
 * deinit:     tear down the channel; called by qcom_mbox_release() and on
 *             init() failure.  Must not fail.
 * process:    advance the state machine; set event bits in *events.
 *             Called by qcom_mbox_process().  Returns TEE_SUCCESS on success.
 * send:       transmit a message; len <= chan->mtu.
 *             Called by qcom_mbox_send().  Returns TEE_SUCCESS on success.
 * recv:       receive a message; updates *len on success.
 *             Called by qcom_mbox_recv().  Returns TEE_SUCCESS on success.
 * rx_pending: return true if at least one message is waiting.
 *             Called by qcom_mbox_process() to refresh the RX_READY level
 *             event.
 */
struct qcom_mbox_ops {
	TEE_Result (*init)(struct qcom_mbox_chan *chan);
	void       (*deinit)(struct qcom_mbox_chan *chan);
	TEE_Result (*process)(struct qcom_mbox_chan *chan, uint32_t *events);
	TEE_Result (*send)(struct qcom_mbox_chan *chan, const void *buf,
			   size_t len);
	TEE_Result (*recv)(struct qcom_mbox_chan *chan, void *buf, size_t *len);
	bool       (*rx_pending)(struct qcom_mbox_chan *chan);
};

/*
 * qcom_mbox_chan_is_ready() - test whether a channel handle is usable.
 *
 * Returns true only when chan is non-NULL and has been successfully
 * initialised via qcom_mbox_request().  Used internally by the framework
 * core to guard all channel operations.
 */
static inline bool qcom_mbox_chan_is_ready(const struct qcom_mbox_chan *chan)
{
	return chan && chan->ready;
}

#endif /* QCOM_MBOX_PRIVATE_H */
