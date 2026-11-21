/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_H
#define QCOM_MBOX_H

/*
 * Mailbox channels to a remote processor. Non-blocking: no call waits for the
 * remote, so the caller polls qcom_mbox_process() and implements its own
 * timeouts. A channel is claimed with qcom_mbox_request() and owned by the
 * caller until qcom_mbox_release(); the caller must serialise all use of it.
 * The claim is a mutex, so those two must be called from thread context.
 *
 * DISCONNECTED and REMOTE_RESET do not need qcom_mbox_release(): the transport
 * renegotiates, so keep polling for the next CONNECTED. Only EVT_ERROR needs a
 * release.
 */

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

struct qcom_mbox_chan;

/*
 * Events returned by qcom_mbox_process().
 *
 * Edge events (latched, returned once per transition):
 *   CONNECTED    - end-to-end connection established; MTU is now valid.
 *   DISCONNECTED - remote endpoint disconnected or closed the channel.
 *   TX_DONE      - remote acknowledged the last sent message, so the mailbox
 *                  is free for the next send. Raised once per
 *                  qcom_mbox_send(); not raised if the channel disconnects
 *                  first.
 *   REMOTE_RESET - remote endpoint reset detected (link went down).
 *
 * Level event (reflects current state on every call):
 *   RX_READY     - at least one received message is waiting in the mailbox.
 *
 * Sticky event (set on first error; remains set until qcom_mbox_release()):
 *   ERROR        - unrecoverable transport failure; channel must be released.
 */
#define QCOM_MBOX_EVT_CONNECTED		BIT32(0)
#define QCOM_MBOX_EVT_DISCONNECTED	BIT32(1)
#define QCOM_MBOX_EVT_RX_READY		BIT32(2)
#define QCOM_MBOX_EVT_TX_DONE		BIT32(3)
#define QCOM_MBOX_EVT_REMOTE_RESET	BIT32(4)
#define QCOM_MBOX_EVT_ERROR		BIT32(5)

/*
 * qcom_mbox_request() - Claim a channel and start connecting it
 * @name: channel name, as listed in the platform's channel table
 * @chan: set to the channel handle on success, NULL on failure
 *
 * Connecting is asynchronous: poll qcom_mbox_process() for
 * QCOM_MBOX_EVT_CONNECTED before sending.
 *
 * Returns:
 *   TEE_ERROR_ITEM_NOT_FOUND no channel with the given name exists.
 *   TEE_ERROR_BAD_STATE      channel configuration is invalid.
 *   TEE_ERROR_BUSY           channel already claimed by another caller.
 *   other                    the transport's init() error.
 */
TEE_Result qcom_mbox_request(const char *name, struct qcom_mbox_chan **chan);

/*
 * qcom_mbox_release() - Tear down a channel and make it requestable again
 * @chan: channel handle, set to NULL
 *
 * Clears a sticky ERROR event. Needed only when the channel is no longer used
 * or after QCOM_MBOX_EVT_ERROR. Does nothing if *@chan is NULL.
 */
void qcom_mbox_release(struct qcom_mbox_chan **chan);

/*
 * qcom_mbox_process() - Advance the transport and collect its events
 * @chan:   channel handle
 * @events: set to the QCOM_MBOX_EVT_* bits raised since the last call. A
 *          transport failure is reported as QCOM_MBOX_EVT_ERROR with a
 *          TEE_SUCCESS return.
 *
 * Returns:
 *   TEE_ERROR_BAD_STATE channel not ready.
 */
TEE_Result qcom_mbox_process(struct qcom_mbox_chan *chan, uint32_t *events);

/*
 * qcom_mbox_send() - Send one message on a connected channel
 * @chan: channel handle
 * @buf:  message to send
 * @len:  message size; must be > 0 and <= the MTU
 *
 * Returns:
 *   TEE_ERROR_BAD_STATE   channel not ready or not connected (MTU is 0).
 *   TEE_ERROR_EXCESS_DATA len exceeds the MTU.
 *   TEE_ERROR_BUSY        mailbox occupied by a previous unacknowledged
 *                         message.
 *   other                 the transport's send() error.
 */
TEE_Result qcom_mbox_send(struct qcom_mbox_chan *chan,
			  const void *buf, size_t len);

/*
 * qcom_mbox_recv() - Copy out the received message
 * @chan: channel handle
 * @buf:  buffer for the message
 * @len:  in: buffer capacity; out: received message size. On
 *        TEE_ERROR_SHORT_BUFFER it is the required size and the message is
 *        preserved in the mailbox, so the caller can retry with a larger
 *        buffer.
 *
 * Returns:
 *   TEE_ERROR_BAD_STATE     channel not ready.
 *   TEE_ERROR_NO_DATA       no message queued.
 *   TEE_ERROR_SHORT_BUFFER  buffer too small.
 *   TEE_ERROR_COMMUNICATION malformed remote data or transport error.
 */
TEE_Result qcom_mbox_recv(struct qcom_mbox_chan *chan,
			  void *buf, size_t *len);

/*
 * qcom_mbox_get_mtu() - Get the largest message the channel can send
 * @chan: channel handle
 * @mtu:  set to the MTU in bytes
 *
 * The MTU is not valid until the transport reports a CONNECTED event.
 *
 * Returns:
 *   TEE_ERROR_BAD_STATE channel not ready.
 *   TEE_ERROR_NO_DATA   MTU not yet negotiated; retry after CONNECTED.
 */
TEE_Result qcom_mbox_get_mtu(struct qcom_mbox_chan *chan, size_t *mtu);

#endif /* QCOM_MBOX_H */
