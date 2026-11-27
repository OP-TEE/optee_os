/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_COM_CLIENT_H
#define __TMEL_COM_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* 1 second, in microseconds */
#define TMEL_COM_DEFAULT_TIMEOUT 1000000

#define TME_STATUS_SUCCESS		0
#define TME_STATUS_INVALID_INPUT	2
#define TME_STATUS_UNKNOWN		0xFFFFFFFF

/*
 * struct tme_sequencer_status - Error status TME-Lite appends to a reply
 * @tme: TME-Lite error status
 * @seq: sequencer error status
 * @kp0: key policy error status, first word
 * @kp1: key policy error status, second word
 * @rsp: sequencer response status
 */
struct tme_sequencer_status {
	uint32_t tme;
	uint32_t seq;
	uint32_t kp0;
	uint32_t kp1;
	uint32_t rsp;
};

/*
 * struct tmel_com_data - Data that goes with a request
 * @in:      data copied into the shared buffer before the request is sent
 * @in_len:  size of @in in bytes; 0 if there is none
 * @out:     buffer the shared buffer's content is copied to after a good reply
 * @out_len: size of @out in bytes; 0 if there is none
 *
 * TME-Lite reads and writes this data at tmel_com_client_data_pa(), so the
 * request has to carry that address. Both sizes are limited to the shared
 * buffer.
 */
struct tmel_com_data {
	const void *in;
	size_t in_len;
	void *out;
	size_t out_len;
};

/*
 * tmel_com_client_data_pa() - Address TME-Lite sees the shared buffer at
 */
paddr_t tmel_com_client_data_pa(void);

/*
 * tmel_com_client_send_message() - Send one request and wait for the reply
 * @tme_msg_uid:  message UID, from tmel_messages_uids.h
 * @timeout:      how long to wait for the reply, in microseconds
 * @payload:      request, overwritten with the reply
 * @payload_len:  size of @payload in bytes; at most the SRAM IPC buffer size
 * @data:         data that goes with the request, or NULL; the shared buffer
 *                is scrubbed before the call returns
 *
 * Takes a mutex, so call it from thread context only.
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @payload is NULL, @payload_len is 0 or too large,
 *                            or @data does not fit the shared buffer.
 *   TEE_ERROR_BAD_STATE      the session is not up.
 *   TEE_ERROR_GENERIC        TME-Lite is not connected, or it replied with a
 *                            non-zero response code.
 *   TEE_ERROR_TIMEOUT        TME-Lite did not reply in time.
 *   TEE_ERROR_COMMUNICATION  mailbox failure or malformed reply.
 */
TEE_Result tmel_com_client_send_message(uint32_t tme_msg_uid, uint32_t timeout,
					void *payload, uint32_t payload_len,
					const struct tmel_com_data *data);

/*
 * tme_status_to_tee_result() - Map a TME-Lite status word to a TEE_Result
 * @tme_status: status from a reply
 */
TEE_Result tme_status_to_tee_result(uint32_t tme_status);

#endif /* __TMEL_COM_CLIENT_H */
