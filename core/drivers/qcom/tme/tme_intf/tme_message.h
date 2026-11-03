/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TME_MESSAGE_H
#define __TME_MESSAGE_H

#include <qcbor.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#include "tme_transport.h"

/* Max supported length of a CBOR request */
#define TME_MAX_CBOR_REQ_LEN	(TMECOM_MAX_REQUEST_SIZE - \
				 sizeof(tme_msg_hdr_t))

/* Max supported length of a CBOR response */
#define TME_MAX_CBOR_RSP_LEN	(TMECOM_MAX_RESPONSE_SIZE - \
				 sizeof(tme_msg_hdr_t))

/*
 * tme_get_encoded_number_size() - calculate the number of bytes required to
 * encode the size of the number passed in
 *
 * @number: A number to find out the number of CBOR bytes required to encode it
 *
 * Return the number of bytes to encode @number.
 */
size_t tme_get_encoded_number_size(uint64_t number);

/*
 * tme_get_max_request_payload() - get the capacity of a CBOR request message
 * that can be sent to the TME firmware. Takes into account the maximum number
 * of bytes to encode the CBOR tag and the maximum number of bytes to encode the
 * CBOR length.
 *
 * Return the maximum CBOR request size.
 */
size_t tme_get_max_request_payload(void);

/*
 * tme_get_max_response_payload() - get the capacity of a CBOR message that can
 * be received from the TME firmware. Takes into account the maximum number of
 * bytes to encode the CBOR tag and the maximum number of bytes to encode the
 * CBOR length.
 *
 * Return the maximum CBOR response size.
 */
size_t tme_get_max_response_payload(void);

/*
 * tme_encode_message() - QCBOR encode a message. Helper function to encode a
 * packed request structure.
 *
 * @tag:          QCBOR tag as per tme_tags.h
 * @message_buf:  Input message buffer
 * @encoded_buf:  In: output buffer for the encoded message. Out: its length
 *                is the length of the encoded message.
 *
 * Return TEE_SUCCESS, or an error code.
 */
TEE_Result tme_encode_message(uint32_t tag, const UsefulBufC message_buf,
			      UsefulBuf *encoded_buf);

/*
 * tme_decode_message() - QCBOR decode a message. Helper function to decode a
 * packed response structure.
 *
 * @tag:          QCBOR tag as per tme_tags.h
 * @encoded_buf:  Input encoded buffer
 * @message_buf:  In: output buffer for the message. Out: its length is the
 *                length of the message.
 *
 * Return TEE_SUCCESS, or an error code.
 */
TEE_Result tme_decode_message(uint32_t tag, const UsefulBufC encoded_buf,
			      UsefulBuf *message_buf);

/*
 * tme_transceive_message() - Helper function to QCBOR encode a request sent to
 * the TME and QCBOR decode the response. This uses a default timeout of
 * TMECOM_RESPONSE_TIMEOUT_MS.
 *
 * @tag:                QCBOR tag as per tme_tags.h
 * @req_buf:            Pointer to a buffer to send to the TME
 * @req_buf_len:        Size of the buffer to send to the TME (in bytes)
 * @resp_buf:           Pointer to a buffer to receive a response from the TME
 * @resp_buf_capacity:  Size of the buffer to receive a response from the TME
 *                      (in bytes)
 * @resp_buf_len:       Number of bytes received
 *
 * Return TEE_SUCCESS, or an error code.
 */
TEE_Result tme_transceive_message(uint32_t tag, void *req_buf,
				  size_t req_buf_len, void *resp_buf,
				  size_t resp_buf_capacity,
				  size_t *resp_buf_len);

#endif /* __TME_MESSAGE_H */
