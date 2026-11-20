/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_H
#define QCOM_MBOX_H

/*
 * QMP-Lite mailbox to a remote processor, used through the generic mailbox
 * framework (drivers/mailbox.h). Only mbox_request_channel() waits: up to one
 * second for the connection to come up, TEE_ERROR_TIMEOUT if it does not. The
 * caller serialises all use of the channel, and polls mbox_recv_sync() for the
 * reply and implements its own timeouts.
 *
 * The channel reconnects by itself when the remote resets or closes it: until
 * then mbox_send_sync() and mbox_recv_sync() return TEE_ERROR_BAD_STATE.
 */

#include <drivers/mailbox.h>
#include <stddef.h>

/*
 * struct qcom_mbox_msg - Message given to mbox_send_sync() and
 * mbox_recv_sync()
 * @buf: message to send, or buffer for the received message
 * @len: send: message size, > 0 and <= the mailbox size. recv: in: buffer
 *       capacity; out: received message size. On TEE_ERROR_SHORT_BUFFER it is
 *       the required size and the message stays in the mailbox, so the caller
 *       can retry with a larger buffer.
 *
 * mbox_send_sync() returns:
 *   TEE_ERROR_BAD_STATE   channel not connected.
 *   TEE_ERROR_BUSY        previous message not yet acknowledged by the remote.
 *   TEE_ERROR_EXCESS_DATA len exceeds the mailbox size.
 *
 * mbox_recv_sync() returns:
 *   TEE_ERROR_BAD_STATE     channel not connected.
 *   TEE_ERROR_NO_DATA       no message queued.
 *   TEE_ERROR_SHORT_BUFFER  buffer too small.
 *   TEE_ERROR_COMMUNICATION malformed remote data.
 */
struct qcom_mbox_msg {
	void *buf;
	size_t len;
};

/*
 * qcom_mbox_get_controller() - Get the controller of the QMP-Lite link
 *
 * Returns NULL if the controller could not be registered.
 */
struct mbox_controller *qcom_mbox_get_controller(void);

#endif /* QCOM_MBOX_H */
