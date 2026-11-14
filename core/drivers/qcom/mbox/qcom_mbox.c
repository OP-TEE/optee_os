// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * mbox_slot_lock guards slot->in_use (and chan->ready on release).
 * Everything else is serialised by the caller.
 */

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <kernel/mutex.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

#include "qcom_mbox_private.h"

static struct mutex mbox_slot_lock = MUTEX_INITIALIZER;

static int plat_data_validate(const struct qcom_mbox_plat_data *pd)
{
	if (!pd || pd->num_channels == 0U || !pd->configs || !pd->slots)
		return -1;
	return 0;
}

static int config_validate(const struct qcom_mbox_chan_config *cfg)
{
	if (!cfg->name || cfg->name[0] == '\0' || !cfg->ops)
		return -1;
	if (!cfg->ops->init || !cfg->ops->deinit ||
	    !cfg->ops->process || !cfg->ops->send ||
	    !cfg->ops->recv || !cfg->ops->rx_pending)
		return -1;
	return 0;
}

static int config_find(const struct qcom_mbox_plat_data *pd,
		       const char *name, size_t *idx)
{
	size_t i = 0;

	for (i = 0U; i < pd->num_channels; i++) {
		if (pd->configs[i].name &&
		    strcmp(pd->configs[i].name, name) == 0) {
			*idx = i;
			return 0;
		}
	}
	return -1;
}

TEE_Result qcom_mbox_request(const char *name, struct qcom_mbox_chan **chan)
{
	const struct qcom_mbox_plat_data *pd = NULL;
	const struct qcom_mbox_chan_config *cfg = NULL;
	struct qcom_mbox_chan_slot *slot = NULL;
	struct qcom_mbox_chan *ch = NULL;
	size_t idx = 0;
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

	if (config_find(pd, name, &idx) != 0) {
		EMSG("qcom_mbox: channel '%s' not found", name);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	cfg = &pd->configs[idx];
	if (config_validate(cfg) != 0) {
		EMSG("qcom_mbox: channel '%s' has invalid config", name);
		return TEE_ERROR_BAD_STATE;
	}

	slot = &pd->slots[idx];

	mutex_lock(&mbox_slot_lock);
	if (slot->in_use) {
		mutex_unlock(&mbox_slot_lock);
		EMSG("qcom_mbox: channel '%s' already in use", name);
		return TEE_ERROR_BUSY;
	}
	slot->in_use = true;
	mutex_unlock(&mbox_slot_lock);

	ch = &slot->chan;
	memset(ch, 0, sizeof(*ch));
	ch->cfg = cfg;

	rc = cfg->ops->init(ch);
	if (rc != TEE_SUCCESS) {
		EMSG("qcom_mbox: channel '%s' init failed: %#x", name, rc);
		memset(ch, 0, sizeof(*ch));
		mutex_lock(&mbox_slot_lock);
		slot->in_use = false;
		mutex_unlock(&mbox_slot_lock);
		return rc;
	}

	ch->ready = true;
	*chan = ch;
	DMSG("qcom_mbox: channel '%s' acquired", name);
	return TEE_SUCCESS;
}

void qcom_mbox_release(struct qcom_mbox_chan *chan)
{
	const struct qcom_mbox_plat_data *pd = NULL;
	struct qcom_mbox_chan_slot *slot = NULL;
	size_t i = 0;

	if (!chan)
		return;

	DMSG("qcom_mbox: release channel '%s'",
	     chan->cfg ? chan->cfg->name : "<unknown>");

	pd = plat_qcom_mbox_get_data();
	if (!pd || !pd->slots)
		return;

	slot = NULL;
	for (i = 0U; i < pd->num_channels; i++) {
		if (&pd->slots[i].chan == chan) {
			slot = &pd->slots[i];
			break;
		}
	}

	mutex_lock(&mbox_slot_lock);
	if (!slot || !slot->in_use || !chan->ready) {
		mutex_unlock(&mbox_slot_lock);
		return;
	}
	chan->ready = false;
	mutex_unlock(&mbox_slot_lock);

	chan->cfg->ops->deinit(chan);
	memset(&slot->chan, 0, sizeof(slot->chan));

	mutex_lock(&mbox_slot_lock);
	slot->in_use = false;
	mutex_unlock(&mbox_slot_lock);
	DMSG("qcom_mbox: channel released");
}

TEE_Result qcom_mbox_process(struct qcom_mbox_chan *chan, uint32_t *events)
{
	uint32_t ev = 0;
	TEE_Result rc = TEE_SUCCESS;

	if (!chan || !events)
		return TEE_ERROR_BAD_PARAMETERS;

	*events = 0U;

	if (!qcom_mbox_chan_is_ready(chan))
		return TEE_SUCCESS;

	rc = chan->cfg->ops->process(chan, &ev);
	if (rc != TEE_SUCCESS || (ev & QCOM_MBOX_EVT_ERROR) != 0U)
		chan->sticky_events |= QCOM_MBOX_EVT_ERROR;

	chan->pending_events |= ev & ~QCOM_MBOX_EVT_ERROR;

	if (chan->cfg->ops->rx_pending(chan))
		chan->pending_events |= QCOM_MBOX_EVT_RX_READY;
	else
		chan->pending_events &= ~QCOM_MBOX_EVT_RX_READY;

	*events = chan->pending_events | chan->sticky_events;

	if (*events)
		DMSG("qcom_mbox: process '%s' events=0x%08x",
		     chan->cfg->name, *events);

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
		return TEE_ERROR_GENERIC;
	if (len > chan->mtu)
		return TEE_ERROR_EXCESS_DATA;

	DMSG("qcom_mbox: send %zu bytes on '%s'", len, chan->cfg->name);
	rc = chan->cfg->ops->send(chan, buf, len);
	if (rc != TEE_SUCCESS)
		EMSG("qcom_mbox: send failed on '%s': %#x",
		     chan->cfg->name, rc);
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
		return TEE_ERROR_GENERIC;

	orig_len = *len;
	rc = chan->cfg->ops->recv(chan, buf, len);
	if (rc == TEE_SUCCESS)
		DMSG("qcom_mbox: recv %zu bytes on '%s'", *len,
		     chan->cfg->name);
	else if (rc != TEE_ERROR_NO_DATA)
		EMSG("qcom_mbox: recv failed on '%s' (buf=%zu): %#x",
		     chan->cfg->name, orig_len, rc);
	return rc;
}

TEE_Result qcom_mbox_get_mtu(struct qcom_mbox_chan *chan, size_t *mtu)
{
	if (!chan || !mtu)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!qcom_mbox_chan_is_ready(chan))
		return TEE_ERROR_BAD_PARAMETERS;
	if (chan->mtu == 0U)
		return TEE_ERROR_NO_DATA;
	*mtu = chan->mtu;
	DMSG("qcom_mbox: get_mtu '%s' = %zu", chan->cfg->name, *mtu);
	return TEE_SUCCESS;
}
