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

/* Direct Request status from the QCOM TEE LSP */
#define TFA_COMM_LSP_ST_SUCCESS		    0
#define TFA_COMM_LSP_ST_FAILURE		    1	/* the LSP could not do it */
#define TFA_COMM_LSP_ST_INVALID_PARAM	2	/* bad register value or size */
#define TFA_COMM_LSP_ST_NOT_SUPPORTED	3	/* unknown FID, UUID, command */
#define TFA_COMM_LSP_ST_DENIED		    4	/* bad origin or sender */

/*
 * tfa_comm_send_direct_req() - send a request to a service of the
 * TF-A QCOM TEE LSP
 *
 * This sends the QCOM TEE LSP in TF-A an FFA_MSG_SEND_DIRECT_REQ2 SMC and
 * waits for the FFA_MSG_SEND_DIRECT_RESP2 response. A service of the LSP is
 * selected by its UUID.
 *
 * @service_uuid:  UUID of the service of the LSP
 * @regs:          In: register values to send to the LSP service
 *                 Out: register values sent by LSP service in response
 *                 Maximum number of registers is TFA_COMM_NUM_REGS
 * @in_buf:        Input buffer to pass to the LSP.
 * @in_size:       Size of @in_buf, at most the size of the shared page.
 * @out_buf:       Buffer that receives the response of the LSP service,
 *                 or NULL if *@out_size is 0.
 * @out_size:      In: size of @out_buf. Out: size of the response of the LSP,
 *                 which is the number of bytes written to @out_buf, 0 if the
 *                 LSP wrote nothing. It can be NULL if no response is expected.
 *                 It is only updated when the LSP reports success, or with
 *                 TEE_ERROR_SHORT_BUFFER.
 *
 * Return TEE_SUCCESS if the LSP reports success, error otherwise
 */
TEE_Result tfa_comm_send_direct_req(const TEE_UUID *service_uuid,
				    uint64_t regs[TFA_COMM_NUM_REGS],
				    const void *in_buf, size_t in_size,
				    void *out_buf, size_t *out_size);

#endif /* DRIVERS_QCOM_TFA_COMM_TFA_COMM_H */
