// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <kernel/mutex.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

#include "qcom_mbox_private.h"

static int plat_data_validate(const struct qcom_mbox_plat_data *pd)
{
	if (!pd || pd->num_channels == 0U || !pd->channels)
		return -1;
	return 0;
}

static int chan_validate(const struct qcom_mbox_chan *chan)
{
	if (!chan->name || chan->name[0] == '\0' || !chan->ops ||
	    !chan->ops->init || !chan->ops->deinit || !chan->ops->process ||
	    !chan->ops->send || !chan->ops->recv || !chan->ops->rx_pending)
		return -1;
	return 0;
}

static struct qcom_mbox_chan *chan_find(const struct qcom_mbox_plat_data *pd,
					const char *name)
{
	size_t i = 0;

	for (i = 0U; i < pd->num_channels; i++) {
		if (pd->channels[i].name &&
		    strcmp(pd->channels[i].name, name) == 0)
			return &pd->channels[i];
	}
	return NULL;
}

static void chan_reset(struct qcom_mbox_chan *chan)
{
	chan->mtu = 0U;
	chan->pending_events = 0U;
	chan->sticky_events = 0U;
	chan->ready = false;
}

TEE_Result qcom_mbox_request(const char *name, struct qcom_mbox_chan **chan)
{
	const struct qcom_mbox_plat_data *pd = NULL;
	struct qcom_mbox_chan *ch = NULL;
	TEE_Result rc = TEE_SUCCESS;

	if (!chan)
		return TEE_ERROR_BAD_PARAMETERS;
	*chan = NULL;

	if (!name || name[0] == '\0')
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("qcom_mbox: request channel '%s'", name);

	pd = plat_qcom_mbox_get_data();
	if (plat_data_validate(pd) != 0) {
		EMSG("qcom_mbox: platform data not available");
		return TEE_ERROR_GENERIC;
	}

	ch = chan_find(pd, name);
	if (!ch) {
		EMSG("qcom_mbox: channel '%s' not found", name);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (chan_validate(ch) != 0) {
		EMSG("qcom_mbox: channel '%s' has invalid config", name);
		return TEE_ERROR_BAD_STATE;
	}

	if (!mutex_trylock(&ch->lock)) {
		EMSG("qcom_mbox: channel '%s' already in use", name);
		return TEE_ERROR_BUSY;
	}

	chan_reset(ch);

	rc = ch->ops->init(ch);
	if (rc != TEE_SUCCESS) {
		EMSG("qcom_mbox: channel '%s' init failed: %#x", name, rc);
		mutex_unlock(&ch->lock);
		return rc;
	}

	ch->ready = true;
	*chan = ch;
	DMSG("qcom_mbox: channel '%s' acquired", name);
	return TEE_SUCCESS;
}

void qcom_mbox_release(struct qcom_mbox_chan **chan)
{
	struct qcom_mbox_chan *ch = NULL;

	if (!chan || !*chan)
		return;

	ch = *chan;
	*chan = NULL;

	DMSG("qcom_mbox: release channel '%s'", ch->name);

	ch->ready = false;
	ch->ops->deinit(ch);
	chan_reset(ch);
	mutex_unlock(&ch->lock);
}

TEE_Result qcom_mbox_process(struct qcom_mbox_chan *chan, uint32_t *events)
{
	uint32_t ev = 0;
	TEE_Result rc = TEE_SUCCESS;

	if (!chan || !events)
		return TEE_ERROR_BAD_PARAMETERS;

	*events = 0U;

	if (!qcom_mbox_chan_is_ready(chan))
		return TEE_ERROR_BAD_STATE;

	rc = chan->ops->process(chan, &ev);
	if (rc != TEE_SUCCESS || (ev & QCOM_MBOX_EVT_ERROR) != 0U)
		chan->sticky_events |= QCOM_MBOX_EVT_ERROR;

	chan->pending_events |= ev & ~QCOM_MBOX_EVT_ERROR;

	if (chan->ops->rx_pending(chan))
		chan->pending_events |= QCOM_MBOX_EVT_RX_READY;
	else
		chan->pending_events &= ~QCOM_MBOX_EVT_RX_READY;

	*events = chan->pending_events | chan->sticky_events;

	if (*events)
		DMSG("qcom_mbox: process '%s' events=0x%08x",
		     chan->name, *events);

	chan->pending_events &= QCOM_MBOX_EVT_RX_READY;

	return TEE_SUCCESS;
}

TEE_Result qcom_mbox_send(struct qcom_mbox_chan *chan,
			  const void *buf, size_t len)
{
	TEE_Result rc = TEE_SUCCESS;

	if (!chan || !buf || len == 0U)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!qcom_mbox_chan_is_ready(chan) || chan->mtu == 0U)
		return TEE_ERROR_BAD_STATE;
	if (len > chan->mtu)
		return TEE_ERROR_EXCESS_DATA;

	DMSG("qcom_mbox: send %zu bytes on '%s'", len, chan->name);
	rc = chan->ops->send(chan, buf, len);
	if (rc != TEE_SUCCESS)
		EMSG("qcom_mbox: send failed on '%s': %#x",
		     chan->name, rc);
	return rc;
}

TEE_Result qcom_mbox_recv(struct qcom_mbox_chan *chan,
			  void *buf, size_t *len)
{
	TEE_Result rc = TEE_SUCCESS;
	size_t orig_len = 0;

	if (!chan || !buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!qcom_mbox_chan_is_ready(chan))
		return TEE_ERROR_BAD_STATE;

	orig_len = *len;
	rc = chan->ops->recv(chan, buf, len);
	if (rc == TEE_SUCCESS)
		DMSG("qcom_mbox: recv %zu bytes on '%s'", *len,
		     chan->name);
	else if (rc != TEE_ERROR_NO_DATA)
		EMSG("qcom_mbox: recv failed on '%s' (buf=%zu): %#x",
		     chan->name, orig_len, rc);
	return rc;
}

TEE_Result qcom_mbox_get_mtu(struct qcom_mbox_chan *chan, size_t *mtu)
{
	if (!chan || !mtu)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!qcom_mbox_chan_is_ready(chan))
		return TEE_ERROR_BAD_STATE;
	if (chan->mtu == 0U)
		return TEE_ERROR_NO_DATA;
	*mtu = chan->mtu;
	DMSG("qcom_mbox: get_mtu '%s' = %zu", chan->name, *mtu);
	return TEE_SUCCESS;
}
