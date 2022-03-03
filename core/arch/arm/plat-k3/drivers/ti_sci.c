// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments System Control Interface Driver
 *   Based on TF-A implementation
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#include <malloc.h>
#include <platform_config.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_defines.h>
#include <trace.h>

#include "sec_proxy.h"
#include "ti_sci.h"
#include "ti_sci_protocol.h"

static uint8_t message_sequence;

/**
 * struct ti_sci_xfer - Structure representing a message flow
 * @tx_message:	Transmit message
 * @rx_message:	Receive message
 */
struct ti_sci_xfer {
	struct k3_sec_proxy_msg tx_message;
	struct k3_sec_proxy_msg rx_message;
};

/**
 * ti_sci_setup_xfer() - Setup message transfer
 *
 * @msg_type:	Message type
 * @msg_flags:	Flag to set for the message
 * @tx_buf:	Buffer to be sent to mailbox channel
 * @tx_message_size: transmit message size
 * @rx_buf:	Buffer to be received from mailbox channel
 * @rx_message_size: receive message size
 * @xfer:	Transfer message
 *
 * Helper function which is used by various command functions that are
 * exposed to clients of this driver for allocating a message traffic event.
 *
 * Return: 0 if all goes well, else appropriate error message
 */
static int ti_sci_setup_xfer(uint16_t msg_type, uint32_t msg_flags,
			     void *tx_buf,
			     size_t tx_message_size,
			     void *rx_buf,
			     size_t rx_message_size,
			     struct ti_sci_xfer *xfer)
{
	struct ti_sci_msg_hdr *hdr = NULL;

	/* Ensure we have sane transfer sizes */
	if (rx_message_size > SEC_PROXY_MAX_MSG_SIZE ||
	    tx_message_size > SEC_PROXY_MAX_MSG_SIZE ||
	    rx_message_size < sizeof(*hdr) ||
	    tx_message_size < sizeof(*hdr)) {
		EMSG("Message transfer size not sane");
		return TEE_ERROR_SHORT_BUFFER;
	}

	hdr = (struct ti_sci_msg_hdr *)tx_buf;
	hdr->seq = ++message_sequence;
	hdr->type = msg_type;
	hdr->host = OPTEE_HOST_ID;
	hdr->flags = msg_flags | TI_SCI_FLAG_REQ_ACK_ON_PROCESSED;

	xfer->tx_message.buf = tx_buf;
	xfer->tx_message.len = tx_message_size;

	xfer->rx_message.buf = rx_buf;
	xfer->rx_message.len = rx_message_size;

	return 0;
}

/**
 * ti_sci_get_response() - Receive response from mailbox channel
 *
 * @xfer:	Transfer to initiate and wait for response
 *
 * Return: 0 if all goes well, else appropriate error message
 */
static inline int ti_sci_get_response(struct ti_sci_xfer *xfer)
{
	struct k3_sec_proxy_msg *msg = &xfer->rx_message;
	struct ti_sci_msg_hdr *hdr = NULL;
	unsigned int retry = 5;
	int ret = 0;

	for (; retry > 0; retry--) {
		/* Receive the response */
		ret = k3_sec_proxy_recv(msg);
		if (ret) {
			EMSG("Message receive failed (%d)", ret);
			return ret;
		}

		/* msg is updated by Secure Proxy driver */
		hdr = (struct ti_sci_msg_hdr *)msg->buf;

		/* Sanity check for message response */
		if (hdr->seq == message_sequence)
			break;

		IMSG("Message with sequence ID %u is not expected", hdr->seq);
	}
	if (!retry) {
		EMSG("Timed out waiting for message");
		return TEE_ERROR_BUSY;
	}

	if (!(hdr->flags & TI_SCI_FLAG_RESP_GENERIC_ACK)) {
		EMSG("Message not acknowledged");
		return TEE_ERROR_GENERIC;
	}

	return 0;
}

/**
 * ti_sci_do_xfer() - Do one transfer
 *
 * @xfer: Transfer to initiate and wait for response
 *
 * Return: 0 if all goes well, else appropriate error message
 */
static inline int ti_sci_do_xfer(struct ti_sci_xfer *xfer)
{
	struct k3_sec_proxy_msg *msg = &xfer->tx_message;
	int ret = 0;

	/* Send the message */
	ret = k3_sec_proxy_send(msg);
	if (ret) {
		EMSG("Message sending failed (%d)", ret);
		return ret;
	}

	/* Get the response */
	ret = ti_sci_get_response(xfer);
	if (ret) {
		EMSG("Failed to get response (%d)", ret);
		return ret;
	}

	return 0;
}

/**
 * ti_sci_get_revision() - Get the revision of the SCI entity
 *
 * Updates the SCI information in the internal data structure.
 *
 * Return: 0 if all goes well, else appropriate error message
 */
int ti_sci_get_revision(struct ti_sci_msg_resp_version *rev_info)
{
	struct ti_sci_msg_req_version req = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_VERSION, 0x0,
				&req, sizeof(req),
				rev_info, sizeof(*rev_info),
				&xfer);
	if (ret)
		return ret;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	return 0;
}

/**
 * ti_sci_init() - Basic initialization
 *
 * Return: 0 if all goes well, else appropriate error message
 */
int ti_sci_init(void)
{
	struct ti_sci_msg_resp_version rev_info = { };
	int ret = 0;

	ret = ti_sci_get_revision(&rev_info);
	if (ret) {
		EMSG("Unable to communicate with control firmware (%d)", ret);
		return ret;
	}

	IMSG("SYSFW ABI: %d.%d (firmware rev 0x%04x '%s')",
	     rev_info.abi_major, rev_info.abi_minor,
	     rev_info.firmware_revision,
	     rev_info.firmware_description);

	return 0;
}
