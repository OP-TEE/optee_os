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
 * struct tme_msg_hdr - Request/Response message header between us and the TME
 */
struct tme_msg_hdr {
	uint16_t version;	/* TMECom version */
	uint16_t crc;		/* Message CRC */
	uint32_t txn_id;	/* Transaction ID */
} __packed;

/*
 * Size of the CBOR encoded part of a request and of a response, the message
 * header not included.
 */
#define TMECOM_MAX_REQUEST_SIZE		1848
#define TMECOM_MAX_RESPONSE_SIZE	2040

#define TMECOM_RESPONSE_TIMEOUT_MS	1000

/* TME request */
struct tme_msg_req {
	struct tme_msg_hdr hdr;
	uint8_t enc_req_buf[TMECOM_MAX_REQUEST_SIZE];
} __aligned(sizeof(uint32_t));

/* TME response */
struct tme_msg_rsp {
	struct tme_msg_hdr hdr;
	uint8_t enc_rsp_buf[TMECOM_MAX_RESPONSE_SIZE];
} __aligned(sizeof(uint32_t));

/*
 * tme_send_recv_message() - send a request to the TME and wait for its response
 *
 * The function is blocking: it does not return until the TME has answered or
 * the timeout expired.
 *
 * @req:         Request message, a struct tme_msg_req, to send to the TME
 * @req_size:    Size in bytes of the request, the header included
 * @resp:        Buffer, a struct tme_msg_rsp, that receives the response
 * @resp_size:   In: size in bytes of the response, the header included, the
 *               buffer can hold. Out: size of the response received.
 * @timeout_ms:  Time in milliseconds the TME has to accept the request, and
 *               the same time again to answer it
 *
 * Return TEE_SUCCESS if everything went fine; error codes otherwise.
 */
TEE_Result tme_send_recv_message(void *req, size_t req_size, void *resp,
				 size_t *resp_size, uint32_t timeout_ms);

#endif /* __TME_TRANSPORT_H */
