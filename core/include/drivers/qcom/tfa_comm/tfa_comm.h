/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef DRIVERS_QCOM_TFA_COMM_TFA_COMM_H
#define DRIVERS_QCOM_TFA_COMM_TFA_COMM_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * Number of registers, x6..x17, that a request and a response carry for the
 * service. x4 and x5 are reserved by tfa_comm. In a request x4 is 0 and x5 is
 * the size of the input buffer. In a response x4 is the status of the LSP and
 * x5 is the size of the output buffer.
 */
#define TFA_COMM_NUM_REGS	12

/*
 * tfa_comm_send_direct_req() - send a request to a service of the TF-A LSP
 *
 * The LSP is the logical partition of the EL3 SPMC in TF-A. This sends it a
 * FFA_MSG_SEND_DIRECT_REQ2 and waits for the FFA_MSG_SEND_DIRECT_RESP2. A
 * service of the LSP is selected by its UUID. The commands of the service and
 * the meaning of the registers x6..x17 for each of them are defined by the
 * service.
 *
 * The buffers go through one page of secure memory shared with the LSP. The
 * page is used by one request at a time: the function takes the lock of the
 * page, copies @in_buf into it, makes the call, copies the response of the LSP
 * from it into @out_buf and releases the lock. The size of @in_buf is sent to
 * the LSP in x5, and the LSP returns in x5 the size of the response that it
 * wrote to the page, 0 if it wrote nothing. The registers x6..x17 of a service
 * do not carry these sizes.
 *
 * The function can sleep on the lock of the page, so it can only be called
 * from a thread context.
 *
 * @service_uuid:  UUID of the service of the LSP
 * @regs:          In: values sent in x6..x17, regs[0] is x6. Out: values
 *                 received in x6..x17, written whenever the LSP answered, even
 *                 if it reported an error.
 * @in_buf:        Buffer copied to the shared page before the call, or NULL
 *                 if @in_size is 0
 * @in_size:       Size of @in_buf, at most the size of the shared page. It is
 *                 sent in x5, and is 0 if there is no input buffer.
 * @out_buf:       Buffer that receives the response of the LSP, or NULL if
 *                 *@out_size is 0. It is only written when the LSP reports
 *                 success.
 * @out_size:      In: size of @out_buf. Out: size of the response of the LSP,
 *                 which is the number of bytes written to @out_buf, 0 if the
 *                 LSP wrote nothing. It can be NULL if no response is expected.
 *                 It is only updated when the LSP reports success, or with
 *                 TEE_ERROR_SHORT_BUFFER.
 *
 * Return TEE_SUCCESS if the LSP reports success, otherwise the LSP status
 * converted to a TEE error code:
 * - TEE_ERROR_GENERIC: the LSP failed the request
 * - TEE_ERROR_BAD_PARAMETERS: the LSP rejected a register or a size
 * - TEE_ERROR_NOT_SUPPORTED: the LSP does not know the service or the command
 * - TEE_ERROR_ACCESS_DENIED: the LSP refused the caller
 * or one of these errors:
 * - TEE_ERROR_BAD_PARAMETERS: @service_uuid or @regs is NULL, or a buffer
 *   pointer is NULL with a size
 * - TEE_ERROR_EXCESS_DATA: @in_size is larger than the shared page
 * - TEE_ERROR_SHORT_BUFFER: the LSP reports success but its response is larger
 *   than *@out_size, or @out_size is NULL. *@out_size is set to the size of the
 *   response and @out_buf is not written. The LSP has done the request: the
 *   response is lost, and @regs holds the registers of the response.
 * - TEE_ERROR_BAD_STATE: the driver is not initialised
 * - TEE_ERROR_COMMUNICATION: the response is not a valid response of the LSP,
 *   for example its size is larger than the shared page
 * - the error code of an FFA_ERROR sent by the SPMC, for example
 *   TEE_ERROR_NOT_SUPPORTED if the SP manifest does not allow direct requests
 *   of the second kind
 */
TEE_Result tfa_comm_send_direct_req(const TEE_UUID *service_uuid,
				    uint64_t regs[TFA_COMM_NUM_REGS],
				    const void *in_buf, size_t in_size,
				    void *out_buf, size_t *out_size);

#endif /* DRIVERS_QCOM_TFA_COMM_TFA_COMM_H */
