// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Qualcomm mailbox framework core.
 *
 * Provides transport-agnostic channel lifecycle management (request/release),
 * state machine advancement (process), message transfer (send/recv), and
 * optional IRQ-assisted wakeup (enable_irq).
 *
 * All public functions are non-blocking.  No dynamic memory allocation is
 * performed; all channel state is embedded in statically-allocated slot
 * arrays supplied by the platform.
 *
 * Concurrency
 * -----------
 * mbox_slot_lock protects slot->in_use transitions only.  Channel operations
 * (process, send, recv) are not protected by any lock; the caller is
 * responsible for serialising concurrent access to the same channel handle.
 *
 * IRQ fields within struct qcom_mbox_chan are protected by chan->irq_lock,
 * which is a spinlock that masks all exceptions before acquisition.  This
 * allows the IRQ handler to safely read and write IRQ state.
 *
 * Transport error codes
 * ---------------------
 * All transport backend operations (init, process, send, recv) return
 * TEE_Result directly.  The framework core passes these results through to
 * callers without translation.
 *
 * IRQ-assisted wakeup
 * -------------------
 * When a channel has an interrupt configured (cfg->itr_chip != NULL) and
 * the caller has registered a notification callback via qcom_mbox_request(),
 * qcom_mbox_enable_irq(chan, true) registers an interrupt handler and enables
 * the interrupt.
 *
 * The interrupt handler (qcom_mbox_itr_handler):
 *   1. Masks the interrupt to prevent storm.
 *   2. Sets chan->irq_pending under chan->irq_lock.
 *   3. Reads the callback pointer under chan->irq_lock.
 *   4. Releases chan->irq_lock.
 *   5. Invokes the callback (if non-NULL) from hard-interrupt context.
 *
 * qcom_mbox_process() re-arms the interrupt after clearing irq_pending,
 * ensuring the interrupt fires again only after the transport has had a
 * chance to consume the event.
 *
 * qcom_mbox_enable_irq(chan, false) disables the interrupt and removes the
 * handler.  After it returns, no further callback invocations will occur.
 *
 * qcom_mbox_release() calls qcom_mbox_enable_irq(chan, false) before
 * tearing down the channel, ensuring the handler cannot access a released
 * channel.
 */

#include <string.h>

#include <kernel/interrupt.h>
#include <kernel/spinlock.h>
#include <tee_api_types.h>
#include <trace.h>

#include <drivers/qcom/mbox/qcom_mbox.h>
#include <drivers/qcom/mbox/qcom_mbox_plat.h>
#include "qcom_mbox_private.h"

/* Protects in_use transitions for all channel slots. */
static unsigned int mbox_slot_lock;

/* --------------------------------------------------------------------------
 * Internal helpers — return 0 on success, -1 on failure.
 * --------------------------------------------------------------------------
 */

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

/* --------------------------------------------------------------------------
 * IRQ handler
 * --------------------------------------------------------------------------
 *
 * Called from hard-interrupt context.  Masks the interrupt to prevent storm,
 * latches irq_pending, then invokes the notification callback (if any) after
 * releasing irq_lock.  The callback runs with irq_lock released and
 * interrupts masked for the current CPU.
 *
 * The interrupt is re-armed by qcom_mbox_process() after it clears
 * irq_pending, ensuring the transport has consumed the event before the
 * interrupt can fire again.
 */
static enum itr_return qcom_mbox_itr_handler(struct itr_handler *h)
{
	struct qcom_mbox_chan *chan = h->data;
	qcom_mbox_notify_cb_t cb = NULL;
	void *priv = NULL;
	uint32_t exceptions = 0;

	/*
	 * Mask the interrupt immediately to prevent an interrupt storm while
	 * the event is being processed.  The interrupt is re-armed by
	 * qcom_mbox_process() after irq_pending is cleared.
	 */
	interrupt_mask(chan->cfg->itr_chip, chan->cfg->itr_num);

	exceptions = cpu_spin_lock_xsave(&chan->irq_lock);
	chan->irq_pending = true;
	cb = chan->notify_cb;
	priv = chan->notify_priv;
	cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);

	/*
	 * Invoke the callback outside the lock.  The callback runs in
	 * hard-interrupt context with interrupts masked.  It must not call
	 * any mailbox API function.
	 */
	if (cb)
		cb(chan, priv);

	return ITRR_HANDLED;
}

/* --------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------
 */

TEE_Result qcom_mbox_request(const char *name,
			     qcom_mbox_notify_cb_t cb, void *priv,
			     struct qcom_mbox_chan **chan)
{
	const struct qcom_mbox_plat_data *pd = NULL;
	const struct qcom_mbox_chan_config *cfg = NULL;
	struct qcom_mbox_chan_slot *slot = NULL;
	struct qcom_mbox_chan *ch = NULL;
	size_t idx = 0;
	uint32_t exceptions = 0;
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

	exceptions = cpu_spin_lock_xsave(&mbox_slot_lock);
	if (slot->in_use) {
		cpu_spin_unlock_xrestore(&mbox_slot_lock, exceptions);
		EMSG("qcom_mbox: channel '%s' already in use", name);
		return TEE_ERROR_BUSY;
	}
	slot->in_use = true;
	cpu_spin_unlock_xrestore(&mbox_slot_lock, exceptions);

	ch = &slot->chan;
	memset(ch, 0, sizeof(*ch));
	ch->cfg = cfg;
	ch->notify_cb = cb;
	ch->notify_priv = priv;

	rc = cfg->ops->init(ch);
	if (rc != TEE_SUCCESS) {
		EMSG("qcom_mbox: channel '%s' init failed: %#x", name, rc);
		cfg->ops->deinit(ch);
		memset(ch, 0, sizeof(*ch));
		exceptions = cpu_spin_lock_xsave(&mbox_slot_lock);
		slot->in_use = false;
		cpu_spin_unlock_xrestore(&mbox_slot_lock, exceptions);
		return rc;
	}

	ch->ready = true;
	*chan = ch;
	DMSG("qcom_mbox: channel '%s' acquired (irq_cb=%s)", name,
	     cb ? "registered" : "none");
	return TEE_SUCCESS;
}

void qcom_mbox_release(struct qcom_mbox_chan *chan)
{
	const struct qcom_mbox_plat_data *pd = NULL;
	struct qcom_mbox_chan_slot *slot = NULL;
	size_t i = 0;
	uint32_t exceptions = 0;

	if (!chan)
		return;

	DMSG("qcom_mbox: release channel '%s'",
	     chan->cfg ? chan->cfg->name : "<unknown>");

	/*
	 * Disable IRQ before tearing down the channel.  This ensures the
	 * interrupt handler cannot access the channel after it is released.
	 */
	qcom_mbox_enable_irq(chan, false);

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

	exceptions = cpu_spin_lock_xsave(&mbox_slot_lock);
	if (!slot || !slot->in_use || !chan->ready) {
		cpu_spin_unlock_xrestore(&mbox_slot_lock, exceptions);
		return;
	}
	chan->ready = false;
	cpu_spin_unlock_xrestore(&mbox_slot_lock, exceptions);

	chan->cfg->ops->deinit(chan);
	memset(&slot->chan, 0, sizeof(slot->chan));

	exceptions = cpu_spin_lock_xsave(&mbox_slot_lock);
	slot->in_use = false;
	cpu_spin_unlock_xrestore(&mbox_slot_lock, exceptions);
	DMSG("qcom_mbox: channel released");
}

TEE_Result qcom_mbox_process(struct qcom_mbox_chan *chan, uint32_t *events)
{
	uint32_t ev = 0;
	uint32_t exceptions = 0;
	bool was_pending = false;
	TEE_Result rc = TEE_SUCCESS;

	if (!chan || !events)
		return TEE_ERROR_BAD_PARAMETERS;

	*events = 0U;

	if (!qcom_mbox_chan_is_ready(chan)) {
		/* Channel not yet ready — not an error, just no events. */
		return TEE_SUCCESS;
	}

	rc = chan->cfg->ops->process(chan, &ev);
	if (rc != TEE_SUCCESS || (ev & QCOM_MBOX_EVT_ERROR) != 0U)
		chan->sticky_events |= QCOM_MBOX_EVT_ERROR;

	/*
	 * Accumulate non-error edge events; ERROR is handled as sticky
	 * above.
	 */
	chan->pending_events |= ev & ~QCOM_MBOX_EVT_ERROR;

	/* Refresh the RX_READY level event from the transport. */
	if (chan->cfg->ops->rx_pending(chan))
		chan->pending_events |= QCOM_MBOX_EVT_RX_READY;
	else
		chan->pending_events &= ~QCOM_MBOX_EVT_RX_READY;

	*events = chan->pending_events | chan->sticky_events;

	if (*events)
		DMSG("qcom_mbox: process '%s' events=0x%08x",
		     chan->cfg->name, *events);

	/* Clear edge events; retain RX_READY (level) for the next call. */
	chan->pending_events &= QCOM_MBOX_EVT_RX_READY;

	/*
	 * Re-arm the interrupt if IRQ-assisted wakeup is enabled and a
	 * notification was pending.  Clear irq_pending first so that any
	 * new event arriving after this point will trigger a fresh interrupt
	 * when the interrupt is unmasked.
	 */
	exceptions = cpu_spin_lock_xsave(&chan->irq_lock);
	was_pending = chan->irq_pending;
	if (was_pending)
		chan->irq_pending = false;
	cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);

	if (was_pending && chan->irq_enabled)
		interrupt_unmask(chan->cfg->itr_chip, chan->cfg->itr_num);

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
	if (chan->mtu == 0U) {
		/*
		 * MTU is not yet valid.  The transport sets chan->mtu when the
		 * shared layout is validated.  The caller should poll with
		 * qcom_mbox_process() and retry after QCOM_MBOX_EVT_CONNECTED.
		 */
		return TEE_ERROR_NO_DATA;
	}
	*mtu = chan->mtu;
	DMSG("qcom_mbox: get_mtu '%s' = %zu", chan->cfg->name, *mtu);
	return TEE_SUCCESS;
}

TEE_Result qcom_mbox_enable_irq(struct qcom_mbox_chan *chan, bool enable)
{
	struct itr_handler *hdlr = NULL;
	uint32_t exceptions = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!chan)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!chan->ready)
		return TEE_ERROR_BAD_STATE;

	DMSG("qcom_mbox: enable_irq '%s' %s",
	     chan->cfg->name, enable ? "enable" : "disable");

	if (enable) {
		/* Check for IRQ configuration. */
		if (!chan->cfg->itr_chip)
			return TEE_ERROR_NOT_SUPPORTED;

		/* Idempotent: already enabled. */
		exceptions = cpu_spin_lock_xsave(&chan->irq_lock);
		if (chan->irq_enabled) {
			cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);
			return TEE_SUCCESS;
		}
		cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);

		/*
		 * Allocate and register the interrupt handler.  This is done
		 * outside the lock because interrupt_alloc_add_conf_handler()
		 * may allocate memory.
		 */
		res = interrupt_alloc_add_conf_handler(chan->cfg->itr_chip,
						       chan->cfg->itr_num,
						       qcom_mbox_itr_handler,
						       ITRF_TRIGGER_LEVEL,
						       chan, IRQ_TYPE_NONE,
						       0, &hdlr);
		if (res != TEE_SUCCESS) {
			EMSG("qcom_mbox: failed to register IRQ handler: %#x",
			     res);
			return TEE_ERROR_GENERIC;
		}

		/*
		 * Enable the interrupt before updating irq_enabled so that
		 * any event that arrived between the lock release above and
		 * the enable below is not lost.
		 */
		interrupt_enable(chan->cfg->itr_chip, chan->cfg->itr_num);

		exceptions = cpu_spin_lock_xsave(&chan->irq_lock);
		if (!chan->ready) {
			/*
			 * Channel was released while we were setting up.
			 * Roll back.
			 */
			cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);
			interrupt_disable(chan->cfg->itr_chip,
					  chan->cfg->itr_num);
			interrupt_remove_free_handler(hdlr);
			return TEE_ERROR_BAD_STATE;
		}
		chan->itr_hdlr = hdlr;
		chan->irq_enabled = true;
		cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);
		DMSG("qcom_mbox: IRQ %u enabled on '%s'",
		     chan->cfg->itr_num, chan->cfg->name);
	} else {
		/* Idempotent: already disabled. */
		exceptions = cpu_spin_lock_xsave(&chan->irq_lock);
		if (!chan->irq_enabled) {
			cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);
			return TEE_SUCCESS;
		}
		hdlr = chan->itr_hdlr;
		chan->itr_hdlr = NULL;
		chan->irq_enabled = false;
		cpu_spin_unlock_xrestore(&chan->irq_lock, exceptions);

		/*
		 * Disable and remove the handler outside the lock.
		 * After interrupt_disable() returns, the interrupt will not
		 * fire again.  After interrupt_remove_free_handler() returns,
		 * the handler function will not be called again.
		 */
		interrupt_disable(chan->cfg->itr_chip, chan->cfg->itr_num);
		interrupt_remove_free_handler(hdlr);
		DMSG("qcom_mbox: IRQ disabled on '%s'", chan->cfg->name);
	}

	return TEE_SUCCESS;
}
