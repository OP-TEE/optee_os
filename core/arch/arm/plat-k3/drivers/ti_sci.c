// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments System Control Interface Driver
 *   Based on TF-A implementation
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#include <assert.h>
#include <kernel/mutex.h>
#include <malloc.h>
#include <platform_config.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_defines.h>
#include <trace.h>

#include "ti_sci.h"
#include "ti_sci_protocol.h"
#include "ti_sci_transport.h"

#define TI_SCI_MAX_MESSAGE_SIZE		56

/**
 * struct ti_sci_xfer - Structure representing a message flow
 * @tx_message:	Transmit message
 * @rx_message:	Receive message
 */
struct ti_sci_xfer {
	struct ti_sci_msg tx_message;
	struct ti_sci_msg rx_message;
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
	if (rx_message_size > TI_SCI_MAX_MESSAGE_SIZE ||
	    tx_message_size > TI_SCI_MAX_MESSAGE_SIZE ||
	    rx_message_size < sizeof(*hdr) ||
	    tx_message_size < sizeof(*hdr)) {
		EMSG("Message transfer size not sane");
		return TEE_ERROR_SHORT_BUFFER;
	}

	hdr = (struct ti_sci_msg_hdr *)tx_buf;
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
 * ti_sci_do_xfer() - Do one transfer
 *
 * @xfer: Transfer to initiate and wait for response
 *
 * Return: 0 if all goes well, else appropriate error message
 */
static int ti_sci_do_xfer(struct ti_sci_xfer *xfer)
{
	struct ti_sci_msg *txmsg = &xfer->tx_message;
	struct ti_sci_msg *rxmsg = &xfer->rx_message;
	struct ti_sci_msg_hdr *txhdr = (struct ti_sci_msg_hdr *)txmsg->buf;
	struct ti_sci_msg_hdr *rxhdr = (struct ti_sci_msg_hdr *)rxmsg->buf;
	static uint8_t message_sequence;
	static struct mutex ti_sci_mutex_lock = MUTEX_INITIALIZER;
	unsigned int retry = 5;
	int ret = 0;

	mutex_lock(&ti_sci_mutex_lock);

	message_sequence++;
	txhdr->seq = message_sequence;

	ret = ti_sci_transport_clear_thread(THREAD_DIR_TX);
	if (ret) {
		EMSG("Failed to clear thread or verification failed\n");
		goto unlock;
	}

	/* Send the message */
	ret = ti_sci_transport_send(txmsg);
	if (ret) {
		EMSG("Message sending failed (%d)", ret);
		goto unlock;
	}

	FMSG("Sending %"PRIx16" with seq %"PRIu8" host %"PRIu8,
	     txhdr->type, txhdr->seq, txhdr->host);

	/* Get the response */
	for (; retry > 0; retry--) {
		/* Receive the response */
		ret = ti_sci_transport_recv(rxmsg);
		if (ret) {
			EMSG("Message receive failed (%d)", ret);
			goto unlock;
		}

		/* Sanity check for message response */
		if (rxhdr->seq == message_sequence)
			break;

		IMSG("Message with sequence ID %"PRIu8" is not expected",
		     rxhdr->seq);
	}
	if (!retry) {
		EMSG("Timed out waiting for message");
		ret = TEE_ERROR_BUSY;
		goto unlock;
	}

	if (!(rxhdr->flags & TI_SCI_FLAG_RESP_GENERIC_ACK)) {
		DMSG("Message not acknowledged");
		ret = TEE_ERROR_ACCESS_DENIED;
		goto unlock;
	}

	FMSG("Receive %"PRIx16" with seq %"PRIu8" host %"PRIu8,
	     rxhdr->type, rxhdr->seq, rxhdr->host);

unlock:
	mutex_unlock(&ti_sci_mutex_lock);
	return ret;
}

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

static int ti_sci_device_set_state(uint32_t id, uint32_t flags, uint8_t state)
{
	struct ti_sci_msg_req_set_device_state req = { };
	struct ti_sci_msg_resp_set_device_state resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_SET_DEVICE_STATE, flags,
				&req, sizeof(req),
				&resp, sizeof(resp),
				&xfer);
	if (ret)
		return ret;

	req.id = id;
	req.state = state;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	return 0;
}

int ti_sci_device_get(uint32_t id)
{
	return ti_sci_device_set_state(id, 0, MSG_DEVICE_SW_STATE_ON);
}

int ti_sci_device_put(uint32_t id)
{
	return ti_sci_device_set_state(id, 0, MSG_DEVICE_SW_STATE_AUTO_OFF);
}

int ti_sci_set_fwl_region(uint16_t fwl_id, uint16_t region,
			  uint32_t n_permission_regs, uint32_t control,
			  const uint32_t permissions[FWL_MAX_PRIVID_SLOTS],
			  uint64_t start_address, uint64_t end_address)
{
	struct ti_sci_msg_req_fwl_set_firewall_region req = { };
	struct ti_sci_msg_resp_fwl_set_firewall_region resp = { };
	struct ti_sci_xfer xfer = { };
	unsigned int i = 0;
	int ret = 0;

	assert(n_permission_regs <= FWL_MAX_PRIVID_SLOTS);

	ret = ti_sci_setup_xfer(TI_SCI_MSG_FWL_SET, 0,
				&req, sizeof(req),
				&resp, sizeof(resp),
				&xfer);
	if (ret)
		return ret;

	req.fwl_id = fwl_id;
	req.region = region;
	req.n_permission_regs = n_permission_regs;
	req.control = control;
	for (i = 0; i < n_permission_regs; i++)
		req.permissions[i] = permissions[i];
	req.start_address = start_address;
	req.end_address = end_address;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	return 0;
}

int ti_sci_get_fwl_region(uint16_t fwl_id, uint16_t region,
			  uint32_t n_permission_regs, uint32_t *control,
			  uint32_t permissions[FWL_MAX_PRIVID_SLOTS],
			  uint64_t *start_address, uint64_t *end_address)
{
	struct ti_sci_msg_req_fwl_get_firewall_region req = { };
	struct ti_sci_msg_resp_fwl_get_firewall_region resp = { };
	struct ti_sci_xfer xfer = { };
	unsigned int i = 0;
	int ret = 0;

	assert(n_permission_regs <= FWL_MAX_PRIVID_SLOTS);

	ret = ti_sci_setup_xfer(TI_SCI_MSG_FWL_GET, 0,
				&req, sizeof(req),
				&resp, sizeof(resp),
				&xfer);
	if (ret)
		return ret;

	req.fwl_id = fwl_id;
	req.region = region;
	req.n_permission_regs = n_permission_regs;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	*control = resp.control;
	for (i = 0; i < n_permission_regs; i++)
		permissions[i] = resp.permissions[i];
	*start_address = resp.start_address;
	*end_address = resp.end_address;

	return 0;
}

int ti_sci_change_fwl_owner(uint16_t fwl_id, uint16_t region,
			    uint8_t owner_index, uint8_t *owner_privid,
			    uint16_t *owner_permission_bits)
{
	struct ti_sci_msg_req_fwl_change_owner_info req = { };
	struct ti_sci_msg_resp_fwl_change_owner_info resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_FWL_CHANGE_OWNER, 0,
				&req, sizeof(req),
				&resp, sizeof(resp),
				&xfer);
	if (ret)
		return ret;

	req.fwl_id = fwl_id;
	req.region = region;
	req.owner_index = owner_index;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	*owner_privid = resp.owner_privid;
	*owner_permission_bits = resp.owner_permission_bits;

	return 0;
}

int ti_sci_get_dkek(uint8_t sa2ul_instance,
		    const char *context, const char *label,
		    uint8_t dkek[SA2UL_DKEK_KEY_LEN])
{
	struct ti_sci_msg_req_sa2ul_get_dkek req = { };
	struct ti_sci_msg_resp_sa2ul_get_dkek resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_SA2UL_GET_DKEK, 0,
				&req, sizeof(req), &resp, sizeof(resp), &xfer);
	if (ret)
		return ret;

	req.sa2ul_instance = sa2ul_instance;
	req.kdf_label_len = strlen(label);
	req.kdf_context_len = strlen(context);
	if (req.kdf_label_len + req.kdf_context_len >
	    KDF_LABEL_AND_CONTEXT_LEN_MAX) {
		EMSG("Context and Label too long");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	memcpy(req.kdf_label_and_context, label, strlen(label));
	memcpy(req.kdf_label_and_context + strlen(label), context,
	       strlen(context));

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	memcpy(dkek, resp.dkek, sizeof(resp.dkek));
	memzero_explicit(&resp, sizeof(resp));
	return 0;
}

int ti_sci_read_otp_mmr(uint8_t mmr_idx, uint32_t *val)
{
	struct ti_sci_msg_req_read_otp_mmr req = { };
	struct ti_sci_msg_resp_read_otp_mmr resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_READ_OTP_MMR, 0,
				&req, sizeof(req), &resp, sizeof(resp), &xfer);
	if (ret)
		goto exit;

	req.mmr_idx = mmr_idx;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		goto exit;

	*val = resp.mmr_val;

exit:
	memzero_explicit(&resp, sizeof(resp));
	return ret;
}

int ti_sci_write_otp_row(uint8_t row_idx, uint32_t row_val, uint32_t row_mask)
{
	struct ti_sci_msg_req_write_otp_row req = { };
	struct ti_sci_msg_resp_write_otp_row resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_WRITE_OTP_ROW, 0,
				&req, sizeof(req), &resp, sizeof(resp), &xfer);
	if (ret)
		goto exit;

	req.row_idx = row_idx;
	req.row_val = row_val;
	req.row_mask = row_mask;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		goto exit;

	DMSG("resp.row_val: 0x%08x", resp.row_val);

	if (resp.row_val != (req.row_val & req.row_mask)) {
		EMSG("Value not written correctly");
		DMSG("req.row_val : 0x%08"PRIx32, req.row_val);
		DMSG("req.row_mask: 0x%08"PRIx32, req.row_mask);
		ret = TEE_ERROR_BAD_STATE;
	}

exit:
	memzero_explicit(&resp, sizeof(resp));
	memzero_explicit(&req, sizeof(req));
	return ret;
}

int ti_sci_lock_otp_row(uint8_t row_idx, uint8_t hw_write_lock,
			uint8_t hw_read_lock, uint8_t row_soft_lock)
{
	struct ti_sci_msg_req_lock_otp_row req = { };
	struct ti_sci_msg_resp_lock_otp_row resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_LOCK_OTP_ROW, 0,
				&req, sizeof(req), &resp, sizeof(resp), &xfer);
	if (ret)
		return ret;

	req.row_idx = row_idx;
	req.hw_write_lock = hw_write_lock;
	req.hw_read_lock = hw_read_lock;
	req.row_soft_lock = row_soft_lock;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	return 0;
}

int ti_sci_set_swrev(uint8_t identifier, uint32_t swrev)
{
	struct ti_sci_msq_req_set_swrev req = { };
	struct ti_sci_msq_resp_set_swrev resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_WRITE_SWREV, 0,
				&req, sizeof(req),
				&resp, sizeof(resp),
				&xfer);
	if (ret)
		return ret;

	req.identifier = identifier;
	req.swrev = swrev;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	memzero_explicit(&req, sizeof(req));
	return 0;
}

int ti_sci_get_swrev(uint32_t *swrev)
{
	struct ti_sci_msq_req_get_swrev req = { };
	struct ti_sci_msq_resp_get_swrev resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_READ_SWREV, 0,
				&req, sizeof(req), &resp, sizeof(resp), &xfer);
	if (ret)
		return ret;

	req.identifier = OTP_REV_ID_SEC_BRDCFG;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	*swrev = resp.swrev;
	memzero_explicit(&resp, sizeof(resp));
	return 0;
}

int ti_sci_get_keycnt_keyrev(uint32_t *key_cnt, uint32_t *key_rev)
{
	struct ti_sci_msq_req_get_keycnt_keyrev req = { };
	struct ti_sci_msq_resp_get_keycnt_keyrev resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_READ_KEYCNT_KEYREV, 0,
				&req, sizeof(req), &resp, sizeof(resp), &xfer);
	if (ret)
		return ret;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	*key_cnt = resp.keycnt;
	*key_rev = resp.keyrev;
	memzero_explicit(&resp, sizeof(resp));
	return 0;
}

int ti_sci_set_keyrev(uint32_t keyrev,
		      uint32_t cert_addr_lo,
		      uint32_t cert_addr_hi)
{
	struct ti_sci_msq_req_set_keyrev req = { };
	struct ti_sci_msq_resp_set_keyrev resp = { };
	struct ti_sci_xfer xfer = { };
	int ret = 0;

	ret = ti_sci_setup_xfer(TI_SCI_MSG_WRITE_KEYREV, 0,
				&req, sizeof(req),
				&resp, sizeof(resp),
				&xfer);
	if (ret)
		return ret;

	req.value = keyrev;
	req.cert_addr_lo = cert_addr_lo;
	req.cert_addr_hi = cert_addr_hi;

	ret = ti_sci_do_xfer(&xfer);
	if (ret)
		return ret;

	memzero_explicit(&req, sizeof(req));
	return 0;
}

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
