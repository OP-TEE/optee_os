/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_PRIVATE_H
#define QCOM_MBOX_PRIVATE_H

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <kernel/mutex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * struct qcom_mbox_ops - Transport operations; all six are mandatory
 * @init:       set up the transport. On failure it cleans up itself and
 *              deinit() is not called.
 * @deinit:     tear the transport down; called only after a successful init()
 * @process:    run the transport state machine and report what happened as
 *              event bits in *events; a non-TEE_SUCCESS return latches
 *              QCOM_MBOX_EVT_ERROR
 * @send:       send a message; the framework guarantees 0 < len <= chan->mtu
 * @recv:       copy the received message to the caller; *len is the buffer
 *              size on entry and the message size on return
 * @rx_pending: tell whether a message is waiting; drives the RX_READY level
 *              event
 */
struct qcom_mbox_ops {
	TEE_Result (*init)(struct qcom_mbox_chan *chan);
	void (*deinit)(struct qcom_mbox_chan *chan);
	TEE_Result (*process)(struct qcom_mbox_chan *chan, uint32_t *events);
	TEE_Result (*send)(struct qcom_mbox_chan *chan, const void *buf,
			   size_t len);
	TEE_Result (*recv)(struct qcom_mbox_chan *chan, void *buf, size_t *len);
	bool (*rx_pending)(struct qcom_mbox_chan *chan);
};

/*
 * struct qcom_mbox_chan - One mailbox channel
 * @name:           channel name used by qcom_mbox_request()
 * @ops:            transport operations
 * @transport_cfg:  read-only transport configuration, owned by the transport
 * @transport_priv: transport state, owned by the transport
 * @lock:           held from qcom_mbox_request() to qcom_mbox_release()
 * @mtu:            TX capacity in bytes; 0 until the transport has completed
 *                  its handshake, and 0 again after a disconnect
 * @pending_events: events raised since the last qcom_mbox_process() call
 * @sticky_events:  latched ERROR event; cleared only on release
 * @ready:          true after a successful init(); cleared on release
 */
struct qcom_mbox_chan {
	const char *name;
	const struct qcom_mbox_ops *ops;
	const void *transport_cfg;
	void *transport_priv;
	/* Claimed with mutex_trylock(): a busy channel fails, never waits */
	struct mutex lock;
	size_t mtu;
	uint32_t pending_events;
	uint32_t sticky_events;
	bool ready;
};

/*
 * struct qcom_mbox_plat_data - Channel table of the platform
 * @channels:     the channels; each one is statically allocated and has its
 *                lock initialized
 * @num_channels: number of entries in @channels
 *
 * Both stay valid for the driver's lifetime; the framework neither copies nor
 * caches them.
 */
struct qcom_mbox_plat_data {
	struct qcom_mbox_chan *channels;
	size_t num_channels;
};

/*
 * plat_qcom_mbox_get_data() - Get the platform's channel table
 *
 * Implemented by the SoC code. Returns NULL if the table is not available yet.
 */
const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void);

static inline bool qcom_mbox_chan_is_ready(const struct qcom_mbox_chan *chan)
{
	return chan && chan->ready;
}

#endif /* QCOM_MBOX_PRIVATE_H */
