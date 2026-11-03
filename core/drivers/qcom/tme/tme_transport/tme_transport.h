/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TME_TRANSPORT_H
#define __TME_TRANSPORT_H

#include <compiler.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * tme_msg_hdr_t - Request/Response message header between us and the TME
 *
 * This header precedes any request specific parameters. The transaction ID is
 * used to match a request with its response.
 */
typedef struct {
	uint16_t version;	/* TMECom version */
	uint16_t crc;		/* Message CRC */
	uint32_t txn_id;	/* Transaction ID */
} __packed tme_msg_hdr_t;

/*
 * Size of the CBOR encoded part of a request and of a response, the message
 * header not included. The TME mailbox is 2048 bytes, the request mailbox
 * loses its first 0xC0 bytes to the QMP descriptor.
 */
#define TMECOM_MAX_REQUEST_SIZE		1848
#define TMECOM_MAX_RESPONSE_SIZE	2040

/*
 * Responses from the TME can be slow, depending on the requested operation.
 *
 * Failure to return within the allotted time period is considered terminal as
 * the TME firmware has become unresponsive.
 */
#define TMECOM_RESPONSE_TIMEOUT_MS	10000

/* Request message: header, then the CBOR encoded request */
typedef struct {
	tme_msg_hdr_t hdr;
	uint8_t enc_req_buf[TMECOM_MAX_REQUEST_SIZE];
} __aligned(sizeof(uint32_t)) tme_msg_req_t;

/* Response message: header, then the CBOR encoded response */
typedef struct {
	tme_msg_hdr_t hdr;
	uint8_t enc_rsp_buf[TMECOM_MAX_RESPONSE_SIZE];
} __aligned(sizeof(uint32_t)) tme_msg_rsp_t;

/*
 * tme_send_recv_message() - send a request to the TME and wait for its response
 *
 * This is the interface of the transport, the layer below tme_intf. It is
 * implemented in tme_transport.c on top of tfa_comm, which sends the messages
 * to the TME through the TF-A. It is private to tme_intf: this header is not
 * meant to be included by anything else.
 *
 * The function is blocking: it does not return until the TME has answered or
 * the timeout expired. It can only be called from a thread context, as
 * tfa_comm sleeps on the lock of the shared memory.
 *
 * A protocol failure in the communication with the TF-A is non-recoverable and
 * panics.
 *
 * @req:         Request message, a tme_msg_req_t, to send to the TME
 * @req_size:    Size in bytes of the request, the header included
 * @resp:        Buffer, a tme_msg_rsp_t, that receives the response
 * @resp_size:   In: size in bytes of the response, the header included, the
 *               buffer can hold. Out: size of the response received.
 * @timeout_ms:  Time in milliseconds the TME has to accept the request, and
 *               the same time again to answer it
 *
 * Return TEE_SUCCESS, TEE_ERROR_BAD_PARAMETERS if an argument is NULL or a
 * size is 0, TEE_ERROR_TIMEOUT if the TME did not accept the request or did
 * not answer it in time, or TEE_ERROR_GENERIC if the TME reported an error.
 */
TEE_Result tme_send_recv_message(void *req, size_t req_size, void *resp,
				 size_t *resp_size, uint32_t timeout_ms);

#endif /* __TME_TRANSPORT_H */
