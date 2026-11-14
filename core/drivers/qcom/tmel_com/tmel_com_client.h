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

struct tme_sequencer_status {
	uint32_t tme;
	uint32_t seq;
	uint32_t kp0;
	uint32_t kp1;
	uint32_t rsp;
};

/*
 * Waits until the mailbox connects to TME-Lite. Runs once, as an early
 * initcall; the other calls fail until it has succeeded.
 */
TEE_Result tmel_com_client_session_start(void);

/*
 * Sends one request and waits for the reply, which overwrites @payload.
 *
 * @timeout: how long to wait for the reply, in microseconds.
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @payload is NULL, or @payload_len is 0 or larger
 *                            than the SRAM IPC buffer.
 *   TEE_ERROR_GENERIC        no connected session, or TME-Lite replied with a
 *                            non-zero response code.
 *   TEE_ERROR_TIMEOUT        TME-Lite did not take the request or reply in
 *                            time.
 *   TEE_ERROR_COMMUNICATION  mailbox failure or malformed reply.
 */
TEE_Result tmel_com_client_send_message(uint32_t tme_msg_uid, uint32_t timeout,
					void *payload, uint32_t payload_len);

/*
 * Returns the buffer TME-Lite can read and write, or NULL if @size is 0 or too
 * large or the session was not started. Blocks while another thread holds the
 * buffer, so call it from thread context only.
 *
 * Every successful call must be followed by tmel_com_client_release_buf() from
 * the same thread. Until then no other thread can send a message.
 */
void *tmel_com_client_get_coherent_buf(size_t size, paddr_t *phys_addr);

/* Scrubs the buffer; call it after any response data has been read from it. */
void tmel_com_client_release_buf(void);

TEE_Result tme_status_to_tee_result(uint32_t tme_status);

#endif /* __TMEL_COM_CLIENT_H */
