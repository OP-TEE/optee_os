// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Transport of the messages between tme_intf and the TME, through the TME
 * service of the logical partition (LSP) of the TF-A.
 *
 * The TME answers a request some time after it has accepted it, so a message
 * is exchanged in two steps, like in the asynchronous transport of the QTEE:
 * the request is submitted and gets a handle, then the handle is polled until
 * the TME has the response. The retries and the waiting are done here, the
 * TF-A makes one attempt per command.
 *
 * The commands go through tfa_comm. It reserves x4 and x5 of the direct
 * request (the status of the LSP and the size of the buffer in the shared
 * memory) and leaves x6..x17 to the service. regs[] below is the array of
 * registers of tfa_comm, regs[0] is x6.
 *
 *   TME_CMD_SEND_REQ
 *     in : regs[0] = TME_CMD_SEND_REQ
 *          The request message is in the shared memory, x5 is its size.
 *     out: regs[0] = status of the TME: 0 if it accepted the request,
 *                    TME_E_AGAIN if it is busy, an error code otherwise
 *          regs[1] = handle of the request, valid if regs[0] is 0
 *          Nothing is written to the shared memory, x5 is 0.
 *
 *   TME_CMD_AWAIT_RESP
 *     in : regs[0] = TME_CMD_AWAIT_RESP
 *          regs[1] = handle returned by TME_CMD_SEND_REQ
 *          regs[2] = size of the buffer for the response
 *     out: regs[0] = status of the TME: 0 if the response is there,
 *                    TME_E_IN_PROGRESS if it has not answered yet, an error
 *                    code otherwise
 *          The response message is in the shared memory, x5 is its size, 0
 *          unless regs[0] is 0.
 *
 * TME_E_AGAIN and TME_E_IN_PROGRESS are codes of this service, not errno
 * values. The TME service of the TF-A defines the same values, so the sign of
 * the errors of the TME passthrough API does not matter. Any other non-zero
 * status is an error of that API: it is only logged.
 */

#include <drivers/qcom/tfa_comm/tfa_comm.h>
#include <inttypes.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <trace.h>

#include "tme_transport.h"

/* UUID of the TME service of the LSP, the TF-A must agree */
static const TEE_UUID tme_uuid = {
	0x4dd829e1, 0x7cf3, 0x4dcf,
	{ 0x9e, 0xcc, 0xbd, 0xa4, 0x10, 0xaa, 0x53, 0xe1 }
};

/* Commands of the TME service, sent in regs[TME_REG_CMD] */
#define TME_CMD_SEND_REQ	1	/* Submit a request, get a handle */
#define TME_CMD_AWAIT_RESP	2	/* Poll a handle for the response */

/* Index in regs[] of the arguments and of the results of the commands */
#define TME_REG_CMD		0	/* in: command */
#define TME_REG_STATUS		0	/* out: status of the TME */
#define TME_REG_HANDLE		1	/* SEND_REQ out, AWAIT_RESP in */
#define TME_REG_RSP_CAPACITY	2	/* AWAIT_RESP in: response capacity */

/*
 * Statuses of the TME that the transport acts on. They are codes of this
 * service: the TME service of the TF-A defines the same values and returns them
 * in place of the errors of the TME passthrough API they stand for, whatever
 * the sign of those. They are above any errno value of the TF-A.
 */
#define TME_E_AGAIN		0x100	/* The TME is busy, try again */
#define TME_E_IN_PROGRESS	0x101	/* The TME has not answered yet */

/* Delay between retries while the submit/poll loops wait on the TME */
#define TME_TRANSPORT_RETRY_DELAY_MS	5U
#define TME_TRANSPORT_POLL_DELAY_MS	5U

/* Time in milliseconds since @start, which is from timeout_init_us(0) */
static uint64_t tme_transport_elapsed_ms(uint64_t start)
{
	return (uint64_t)timeout_elapsed_us(start) / 1000;
}

/*
 * Submit the CBOR request to the TME and obtain an async handle.
 *
 * Retries on TME_E_AGAIN (TME busy) until @timeout_ms elapses.
 *
 * Return TEE_SUCCESS with *@handle set, TEE_ERROR_GENERIC or TEE_ERROR_TIMEOUT.
 */
static TEE_Result tme_transport_async_send_request(void *req, size_t req_size,
						   uint32_t *handle,
						   uint32_t timeout_ms)
{
	uint64_t start = timeout_init_us(0);

	do {
		uint64_t regs[TFA_COMM_NUM_REGS] = {
			[TME_REG_CMD] = TME_CMD_SEND_REQ,
		};
		TEE_Result res = TEE_SUCCESS;
		int32_t tme_status = 0;

		res = tfa_comm_send_direct_req(&tme_uuid, regs, req, req_size,
					       NULL, NULL);
		if (res != TEE_SUCCESS) {
			/*
			 * A protocol failure in communication with TME is
			 * non-recoverable
			 */
			EMSG("TME submit transport failure: result %#"PRIx32,
			     res);
			panic("TME: submit transport failure");
		}

		tme_status = (int32_t)regs[TME_REG_STATUS];
		if (tme_status != TME_E_AGAIN) {
			/* Got a non retry status */
			if (tme_status) {
				EMSG("TME submit failed: status %"PRId32,
				     tme_status);
				return TEE_ERROR_GENERIC;
			}

			*handle = (uint32_t)regs[TME_REG_HANDLE];
			return TEE_SUCCESS;
		}

		/* TME is busy, wait the retry delay before trying again */
		mdelay(TME_TRANSPORT_RETRY_DELAY_MS);
	} while (tme_transport_elapsed_ms(start) + TME_TRANSPORT_POLL_DELAY_MS <
		 timeout_ms);

	return TEE_ERROR_TIMEOUT;
}

/*
 * Poll the TME for the CBOR response corresponding to a previously submitted
 * handle.
 *
 * Retries on TME_E_IN_PROGRESS until @timeout_ms elapses.
 *
 * Return TEE_SUCCESS with *@resp_size updated, TEE_ERROR_GENERIC or
 * TEE_ERROR_TIMEOUT.
 */
static TEE_Result tme_transport_async_await_response(uint32_t handle,
						     void *resp,
						     size_t *resp_size,
						     uint32_t timeout_ms)
{
	uint64_t start = timeout_init_us(0);
	size_t resp_capacity = *resp_size;

	do {
		uint64_t regs[TFA_COMM_NUM_REGS] = {
			[TME_REG_CMD] = TME_CMD_AWAIT_RESP,
			[TME_REG_HANDLE] = handle,
			[TME_REG_RSP_CAPACITY] = resp_capacity,
		};
		TEE_Result res = TEE_SUCCESS;
		int32_t tme_status = 0;

		/*
		 * tfa_comm replaces *resp_size with the size of the response,
		 * 0 while the TME has not answered. Give the capacity again.
		 */
		*resp_size = resp_capacity;
		res = tfa_comm_send_direct_req(&tme_uuid, regs, NULL, 0, resp,
					       resp_size);
		if (res == TEE_ERROR_SHORT_BUFFER) {
			/*
			 * TME wrote a response length which is larger than the
			 * supported response length
			 */
			EMSG("TME poll: rsp_len %zu exceeds capacity %zu",
			     *resp_size, resp_capacity);
			panic("TME: poll transport failure");
		}
		if (res != TEE_SUCCESS) {
			/*
			 * A protocol failure in communication with TME is
			 * non-recoverable
			 */
			EMSG("TME poll transport failure: result %#"PRIx32,
			     res);
			panic("TME: poll transport failure");
		}

		tme_status = (int32_t)regs[TME_REG_STATUS];
		if (tme_status != TME_E_IN_PROGRESS) {
			/* Got a non retry status */
			if (tme_status) {
				EMSG("TME poll failed: status %"PRId32,
				     tme_status);
				return TEE_ERROR_GENERIC;
			}

			return TEE_SUCCESS;
		}

		/* TME has not finished, wait the poll delay before polling */
		mdelay(TME_TRANSPORT_POLL_DELAY_MS);
	} while (tme_transport_elapsed_ms(start) + TME_TRANSPORT_POLL_DELAY_MS <
		 timeout_ms);

	return TEE_ERROR_TIMEOUT;
}

TEE_Result tme_send_recv_message(void *req, size_t req_size, void *resp,
				 size_t *resp_size, uint32_t timeout_ms)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t handle = 0;

	if (!req || !resp || !resp_size || !req_size || !*resp_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tme_transport_async_send_request(req, req_size, &handle,
					       timeout_ms);
	if (res != TEE_SUCCESS)
		return res;

	return tme_transport_async_await_response(handle, resp, resp_size,
						  timeout_ms);
}
