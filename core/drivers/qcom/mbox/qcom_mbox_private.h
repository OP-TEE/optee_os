/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_PRIVATE_H
#define QCOM_MBOX_PRIVATE_H

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*
 * All six are mandatory (checked by config_validate()).
 *
 * init:       on failure the transport cleans up itself; deinit() is not
 *             called.
 * deinit:     called only after a successful init().
 * process:    set event bits in *events; a non-TEE_SUCCESS return latches
 *             QCOM_MBOX_EVT_ERROR.
 * send:       the framework guarantees 0 < len <= chan->mtu.
 * recv:       *len is the capacity on entry and the size on return; on
 *             TEE_ERROR_SHORT_BUFFER set it to the needed size and keep the
 *             message queued.
 * rx_pending: drives the RX_READY level event.
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

/* @reg: 0 = do not ring. */
struct qcom_mbox_signal_config {
	vaddr_t		reg;
	uint32_t	value;
};

struct qcom_mbox_chan_config {
	const char			*name;
	const struct qcom_mbox_ops	*ops;
	const void			*transport_cfg;
	void				*transport_priv;
};

/*
 * @ready:         true after a successful init(); cleared on release.
 * @mtu:           TX capacity in bytes; set by the transport while connected,
 *                 0 otherwise.
 * @sticky_events: latched ERROR event; cleared only on release.
 */
struct qcom_mbox_chan {
	const struct qcom_mbox_chan_config	*cfg;
	bool					 ready;
	size_t					 mtu;
	uint32_t				 pending_events;
	uint32_t				 sticky_events;
};

/* @in_use: guarded by mbox_slot_lock. */
struct qcom_mbox_chan_slot {
	struct qcom_mbox_chan	chan;
	bool			in_use;
};

/*
 * configs[N] permanently maps to slots[N]; num_channels is the size of both.
 * All three are statically allocated and stay valid for the driver's lifetime;
 * the framework neither copies nor caches them.
 */
struct qcom_mbox_plat_data {
	const struct qcom_mbox_chan_config	*configs;
	struct qcom_mbox_chan_slot		*slots;
	size_t					 num_channels;
};

/*
 * Implemented by the SoC code: returns the channel table, or NULL if it is not
 * available yet (qcom_mbox_request() then fails with TEE_ERROR_GENERIC).
 */
const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void);

static inline bool qcom_mbox_chan_is_ready(const struct qcom_mbox_chan *chan)
{
	return chan && chan->ready;
}

#endif /* QCOM_MBOX_PRIVATE_H */
