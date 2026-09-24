/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_TYPES_H
#define QCOM_MBOX_TYPES_H

/*
 * Shared type definitions for the Qualcomm mailbox framework.
 *
 * Included by the public API header (qcom_mbox.h), the platform-integration
 * header (qcom_mbox_plat.h), and the driver-internal header
 * (qcom_mbox_private.h).  Must not include any driver-internal headers.
 *
 * IRQ fields
 * ----------
 * struct qcom_mbox_chan embeds the IRQ state managed by the framework core.
 * struct qcom_mbox_chan_config carries the optional interrupt descriptor
 * supplied by the platform.  When itr_chip is NULL the channel operates in
 * polling-only mode and qcom_mbox_enable_irq() returns
 * TEE_ERROR_NOT_SUPPORTED.
 *
 * Forward declarations of struct itr_chip and struct itr_handler avoid a
 * hard dependency on <kernel/interrupt.h> in headers that only need pointer
 * types.  Platform code and the framework core include <kernel/interrupt.h>
 * directly.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward declarations — full definitions in <kernel/interrupt.h>. */
struct itr_chip;
struct itr_handler;

/* Forward declaration — full definition below. */
struct qcom_mbox_chan;

/*
 * qcom_mbox_notify_cb_t — IRQ wakeup notification callback.
 *
 * @chan: channel that received the wakeup notification.
 * @priv: opaque value supplied to qcom_mbox_request().
 *
 * Called from hard-interrupt context with the channel's irq_lock released.
 * Interrupts are masked for the current CPU.  The callback MUST NOT:
 *   - sleep or block
 *   - call qcom_mbox_recv(), qcom_mbox_send(), qcom_mbox_process(), or
 *     qcom_mbox_release()
 *   - call qcom_mbox_enable_irq()
 *   - acquire any lock that may be held by the interrupted thread
 *
 * The callback should set a flag or post to a semaphore so that a thread
 * context can later call qcom_mbox_process() to consume transport events.
 * Notification semantics are coalesced: one callback may represent one or
 * more hardware events.
 */
typedef void (*qcom_mbox_notify_cb_t)(struct qcom_mbox_chan *chan, void *priv);

/*
 * struct qcom_mbox_ops — transport operations table (forward declaration).
 *
 * Full definition is in qcom_mbox_private.h (driver-internal).
 */
struct qcom_mbox_ops;

/*
 * struct qcom_mbox_chan_config — immutable per-channel configuration.
 *
 * Populated by the platform and passed to the framework via
 * struct qcom_mbox_plat_data.  Must remain valid for the lifetime of the
 * driver.
 *
 * @name:           unique null-terminated channel identifier.
 * @ops:            transport operations table; all pointers must be non-NULL.
 * @transport_cfg:  opaque pointer to transport-specific configuration
 *                  (e.g. struct qcom_mbox_qmp_config *).
 * @transport_priv: opaque pointer to transport-specific runtime state
 *                  (e.g. struct qcom_mbox_qmp_priv *).
 * @itr_chip:       interrupt controller for the incoming notification IRQ.
 *                  NULL disables IRQ-assisted wakeup (polling-only mode).
 * @itr_num:        interrupt number within @itr_chip.  Ignored when
 *                  @itr_chip is NULL.
 */
struct qcom_mbox_chan_config {
	const char			*name;
	const struct qcom_mbox_ops	*ops;
	const void			*transport_cfg;
	void				*transport_priv;
	struct itr_chip			*itr_chip;
	size_t				 itr_num;
};

/*
 * struct qcom_mbox_chan — runtime channel handle.
 *
 * Embedded in struct qcom_mbox_chan_slot (one per channel slot).  Returned
 * to callers by qcom_mbox_request().  Callers must treat this as an opaque
 * handle and must not access fields directly.
 *
 * Framework-managed fields:
 * @cfg:            pointer to the static channel configuration.
 * @ready:          true after a successful init(); cleared on release.
 * @mtu:            effective TX capacity in bytes; 0 until transport reports.
 * @pending_events: accumulated edge/level events not yet returned to caller.
 * @sticky_events:  latched error events; cleared only on release.
 *
 * IRQ-assisted wakeup fields (protected by @irq_lock):
 * @notify_cb:      notification callback; NULL in polling-only mode.
 * @notify_priv:    opaque value forwarded to @notify_cb.
 * @itr_hdlr:       allocated interrupt handler; NULL when IRQ is disabled.
 * @irq_enabled:    true when the interrupt is currently enabled.
 * @irq_pending:    set by the IRQ handler; cleared by qcom_mbox_process().
 * @irq_lock:       spinlock protecting all IRQ fields above.
 */
struct qcom_mbox_chan {
	const struct qcom_mbox_chan_config	*cfg;
	bool					 ready;
	size_t					 mtu;
	uint32_t				 pending_events;
	uint32_t				 sticky_events;
	/* IRQ-assisted wakeup state — protected by irq_lock. */
	qcom_mbox_notify_cb_t			 notify_cb;
	void					*notify_priv;
	struct itr_handler			*itr_hdlr;
	bool					 irq_enabled;
	bool					 irq_pending;
	unsigned int				 irq_lock;
};

/*
 * struct qcom_mbox_chan_slot — per-channel runtime slot.
 *
 * Allocated statically by the platform (one per channel).  The framework
 * core owns all fields; backends must not access them directly.
 *
 * @chan:    embedded channel handle returned to callers.
 * @in_use:  true while the slot is claimed; protected by the framework's
 *           internal mbox_slot_lock spinlock.
 */
struct qcom_mbox_chan_slot {
	struct qcom_mbox_chan	chan;
	bool			in_use;
};

#endif /* QCOM_MBOX_TYPES_H */
