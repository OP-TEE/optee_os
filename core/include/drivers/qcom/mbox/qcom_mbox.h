/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_H
#define QCOM_MBOX_H

/*
 * Qualcomm mailbox framework — public API.
 *
 * This header is the only interface that consumers of the mailbox framework
 * should include.  All other headers in this directory are either
 * platform-integration headers (qcom_mbox_plat.h, qcom_mbox_qmp.h,
 * qcom_mbox_qmp_lite.h) or driver-internal headers (qcom_mbox_private.h).
 *
 * Concurrency model
 * -----------------
 * Concurrent access to the same channel handle from multiple CPUs is NOT
 * supported.  The caller is responsible for serializing all operations on a
 * given channel handle.  qcom_mbox_request() and qcom_mbox_release() are
 * protected by an internal spinlock for slot allocation only; channel
 * operations (process, send, recv) are not protected.
 *
 * Polling mode
 * ------------
 * All framework functions are non-blocking and return immediately.  No
 * polling loops, no waits, and no dynamic memory allocation occur inside
 * the framework.  The caller is responsible for implementing any required
 * polling or timeout logic.
 *
 * IRQ-assisted wakeup mode
 * ------------------------
 * When a channel has an interrupt configured (itr_chip != NULL in the
 * platform channel config), the caller may register a notification callback
 * via qcom_mbox_request() and enable the interrupt via qcom_mbox_enable_irq().
 * The callback is invoked from hard-interrupt context when the remote sends
 * a notification.  The callback must not call any mailbox API function.
 * After the callback, the caller must call qcom_mbox_process() from a thread
 * context to consume transport events.  Polling via qcom_mbox_process()
 * remains fully functional regardless of IRQ mode.
 *
 * Reconnection model
 * ------------------
 * QCOM_MBOX_EVT_DISCONNECTED and QCOM_MBOX_EVT_REMOTE_RESET do NOT require
 * the client to call qcom_mbox_release().  The transport automatically
 * re-negotiates.  Continue polling with qcom_mbox_process() and wait for
 * the next QCOM_MBOX_EVT_CONNECTED event.
 *
 * QCOM_MBOX_EVT_ERROR is the only event that requires qcom_mbox_release().
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tee_api_types.h>
#include <util.h>

#include <drivers/qcom/mbox/qcom_mbox_types.h>

/*
 * Event bitmap returned by qcom_mbox_process().
 *
 * Edge events (latched, returned once per transition):
 *   CONNECTED    - end-to-end connection established; MTU is now valid.
 *   DISCONNECTED - remote endpoint disconnected or channel closed.
 *   TX_DONE      - remote endpoint consumed the last sent message; the
 *                  local mailbox is now free for the next send.
 *   REMOTE_RESET - remote endpoint reset detected (link went down).
 *
 * Level event (reflects current state on every call):
 *   RX_READY     - at least one received message is waiting in the mailbox.
 *
 * Sticky event (set on first error; remains set until qcom_mbox_release()):
 *   ERROR        - unrecoverable transport failure; channel must be released.
 *
 * TX_DONE is set exactly once per qcom_mbox_send() call, when the remote
 * endpoint clears the local msg_len field to signal that it has read the
 * message.  It is not set if the channel disconnects before the remote
 * consumes the message.
 */
#define QCOM_MBOX_EVT_CONNECTED		BIT32(0)
#define QCOM_MBOX_EVT_DISCONNECTED	BIT32(1)
#define QCOM_MBOX_EVT_RX_READY		BIT32(2)
#define QCOM_MBOX_EVT_TX_DONE		BIT32(3)
#define QCOM_MBOX_EVT_REMOTE_RESET	BIT32(4)
#define QCOM_MBOX_EVT_ERROR		BIT32(5)

/*
 * qcom_mbox_request() - acquire a mailbox channel by name.
 *
 * Looks up the named channel in the platform channel table, claims a runtime
 * slot, and initialises the transport.  The channel is ready for use when
 * this function returns TEE_SUCCESS.
 *
 * @name: null-terminated channel identifier; must not be NULL or empty.
 * @cb:   optional notification callback invoked from hard-interrupt context
 *        when the remote sends a wakeup notification.  NULL for polling-only
 *        mode.  See qcom_mbox_notify_cb_t for calling-context restrictions.
 * @priv: opaque value forwarded to @cb; may be NULL.
 * @chan: output handle; set to NULL on failure.
 *
 * Returns:
 *   TEE_SUCCESS              on success.
 *   TEE_ERROR_BAD_PARAMETERS name is NULL/empty, or chan is NULL.
 *   TEE_ERROR_GENERIC        platform data unavailable or transport init
 *                            failed.
 *   TEE_ERROR_ITEM_NOT_FOUND no channel with the given name exists.
 *   TEE_ERROR_BAD_STATE      channel configuration is invalid.
 *   TEE_ERROR_BUSY           channel already claimed by another caller.
 */
TEE_Result qcom_mbox_request(const char *name,
			     qcom_mbox_notify_cb_t cb, void *priv,
			     struct qcom_mbox_chan **chan);

/*
 * qcom_mbox_release() - release a previously acquired channel.
 *
 * Disables any active IRQ, tears down the transport connection, and returns
 * the runtime slot to the free pool.  After this call the handle must not
 * be used.  Clears any sticky ERROR event.
 *
 * This function is idempotent: calling it with NULL or an already-released
 * handle has no effect.
 *
 * Note: qcom_mbox_release() is NOT required after DISCONNECTED or
 * REMOTE_RESET events.  The transport reconnects automatically.  Call
 * qcom_mbox_release() only when the channel is no longer needed or when
 * QCOM_MBOX_EVT_ERROR is set.
 *
 * @chan: channel handle; silently ignored if NULL.
 */
void qcom_mbox_release(struct qcom_mbox_chan *chan);

/*
 * qcom_mbox_process() - advance the transport state machine.
 *
 * Polls the transport for new events and advances the connection state
 * machine.  Must be called periodically by the client to collect
 * connection, disconnect, and RX events.
 *
 * If IRQ-assisted wakeup is enabled, qcom_mbox_process() also re-arms the
 * interrupt after clearing the pending notification flag.  The interrupt
 * is re-armed only after this function is called, ensuring that the
 * transport has had a chance to consume the event that triggered the IRQ.
 *
 * @chan:   channel handle; must not be NULL.
 * @events: output bitmap of QCOM_MBOX_EVT_* bits; always written (0 if
 *          no events are pending or on error).
 *
 * Returns:
 *   TEE_SUCCESS              on success (events may be 0).
 *   TEE_ERROR_BAD_PARAMETERS chan or events is NULL.
 */
TEE_Result qcom_mbox_process(struct qcom_mbox_chan *chan, uint32_t *events);

/*
 * qcom_mbox_send() - transmit a message.
 *
 * @chan: channel handle; must not be NULL.
 * @buf:  message buffer; must not be NULL.
 * @len:  message length in bytes; must be > 0 and <= effective MTU.
 *
 * Returns:
 *   TEE_SUCCESS              on success.
 *   TEE_ERROR_BAD_PARAMETERS chan or buf is NULL, or len is 0.
 *   TEE_ERROR_GENERIC        channel not ready or MTU not yet negotiated.
 *   TEE_ERROR_EXCESS_DATA    len exceeds the effective MTU.
 *   TEE_ERROR_BAD_STATE      transport not yet connected.
 *   TEE_ERROR_BUSY           mailbox occupied by a previous unacknowledged
 *                            message.
 *   TEE_ERROR_COMMUNICATION  transport-level error.
 */
TEE_Result qcom_mbox_send(struct qcom_mbox_chan *chan,
			  const void *buf, size_t len);

/*
 * qcom_mbox_recv() - receive a message.
 *
 * On TEE_ERROR_SHORT_BUFFER, *len is updated to the required buffer size
 * and the message is preserved in the mailbox so the caller can retry with
 * a larger buffer.
 *
 * @chan: channel handle; must not be NULL.
 * @buf:  receive buffer; must not be NULL.
 * @len:  in/out: buffer capacity on entry; received message size on success.
 *
 * Returns:
 *   TEE_SUCCESS              on success.
 *   TEE_ERROR_BAD_PARAMETERS chan, buf, or len is NULL.
 *   TEE_ERROR_GENERIC        channel not ready.
 *   TEE_ERROR_NO_DATA        no message queued.
 *   TEE_ERROR_SHORT_BUFFER   buffer too small; *len updated to required size.
 *   TEE_ERROR_COMMUNICATION  malformed remote data or transport error.
 */
TEE_Result qcom_mbox_recv(struct qcom_mbox_chan *chan,
			  void *buf, size_t *len);

/*
 * qcom_mbox_get_mtu() - return the effective MTU of the channel.
 *
 * The MTU is not valid until the transport reports a CONNECTED event.
 * Poll with qcom_mbox_process() and wait for QCOM_MBOX_EVT_CONNECTED
 * before calling this function.
 *
 * @chan: channel handle; must not be NULL.
 * @mtu:  output; set to the effective MTU in bytes on success.
 *
 * Returns:
 *   TEE_SUCCESS              on success.
 *   TEE_ERROR_BAD_PARAMETERS chan or mtu is NULL, or chan is not ready.
 *   TEE_ERROR_NO_DATA        MTU not yet negotiated; retry after CONNECTED.
 */
TEE_Result qcom_mbox_get_mtu(struct qcom_mbox_chan *chan, size_t *mtu);

/*
 * qcom_mbox_enable_irq() - enable or disable IRQ-assisted wakeup.
 *
 * @chan:   channel handle; must be in READY state (returned by a successful
 *          qcom_mbox_request()).
 * @enable: true to enable, false to disable.
 *
 * When @enable is true:
 *   Validates the channel state, registers an interrupt handler, and enables
 *   the incoming interrupt.  The operation is idempotent: calling with true
 *   when already enabled returns TEE_SUCCESS without re-registering.
 *   Returns TEE_ERROR_NOT_SUPPORTED when the platform channel has no IRQ
 *   configuration (itr_chip == NULL).
 *   On failure, any partially registered resources are rolled back and the
 *   channel remains in polling-only mode.
 *
 * When @enable is false:
 *   Disables the incoming interrupt and removes the handler.  Already-latched
 *   irq_pending state and transport events are preserved.  Polling via
 *   qcom_mbox_process() remains fully functional.  The operation is
 *   idempotent: calling with false when already disabled returns TEE_SUCCESS.
 *
 * Synchronization guarantee:
 *   After qcom_mbox_enable_irq(chan, false) returns, no further invocations
 *   of the notification callback will occur for this channel.  Any callback
 *   that was in progress when disable was called will have completed before
 *   this function returns.
 *
 * Returns:
 *   TEE_SUCCESS              on success.
 *   TEE_ERROR_BAD_PARAMETERS chan is NULL.
 *   TEE_ERROR_BAD_STATE      channel is not in READY state.
 *   TEE_ERROR_NOT_SUPPORTED  no IRQ configuration (enable only).
 *   TEE_ERROR_GENERIC        interrupt registration failed (enable only).
 */
TEE_Result qcom_mbox_enable_irq(struct qcom_mbox_chan *chan, bool enable);

#endif /* QCOM_MBOX_H */
