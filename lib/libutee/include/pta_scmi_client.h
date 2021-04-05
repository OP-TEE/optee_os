/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2021, Linaro Limited
 */
#ifndef PTA_SCMI_CLIENT_H
#define PTA_SCMI_CLIENT_H

#define PTA_SCMI_UUID {\
		0xa8cfe406, 0xd4f5, 0x4a2e, \
		{ 0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0x99 } \
	}

#define PTA_SCMI_NAME "PTA-SCMI"

enum optee_smci_pta_cmd {
	/*
	 * PTA_SCMI_CMD_CAPABILITIES - Get channel capabilities
	 *
	 * [out]    value[0].a: Capability bit mask (enum pta_scmi_caps)
	 * [out]    value[0].b: Extended capabilities or 0
	 */
	PTA_SCMI_CMD_CAPABILITIES = 0,

	/*
	 * PTA_SCMI_CMD_PROCESS_SMT_CHANNEL - Process SCMI message in SMT buffer
	 *
	 * [in]     value[0].a: Channel handle
	 *
	 * Shared memory used for SCMI message/response exhange is expected
	 * already identified and bound to channel handle in both SCMI agent
	 * and SCMI server (OP-TEE) parts.
	 * The memory uses SMT header to carry SCMI meta-data (protocol ID and
	 * protocol message ID).
	 */
	PTA_SCMI_CMD_PROCESS_SMT_CHANNEL = 1,

	/*
	 * PTA_SCMI_CMD_PROCESS_SMT_CHANNEL_MESSAGE - Process SMT/SCMI message
	 *
	 * [in]     value[0].a: Channel handle
	 * [in/out] memref[1]: Message/response buffer (SMT and SCMI payload)
	 *
	 * Shared memory used for SCMI message/response is a SMT buffer
	 * referenced by param[1]. It shall be 128 bytes large to fit response
	 * payload whatever message playload size.
	 * The memory uses SMT header to carry SCMI meta-data (protocol ID and
	 * protocol message ID).
	 */
	PTA_SCMI_CMD_PROCESS_SMT_CHANNEL_MESSAGE = 2,

	/*
	 * PTA_SCMI_CMD_GET_CHANNEL - Get channel handle
	 *
	 * [in]     value[0].a: Channel identifier or 0 if no assigned ID
	 * [out]    value[0].a: Returned channel handle
	 * [in]     value[0].b: Requested capabilities mask (enum pta_scmi_caps)
	 */
	PTA_SCMI_CMD_GET_CHANNEL = 3,

	/*
	 * PTA_SCMI_CMD_OCALL_THREAD - Allocate a threaded path using OCALL
	 *
	 * [in]   value[0].a: channel handle
	 *
	 * Use Ocall support to create a provisioned OP-TEE thread context for
	 * the channel. Successful creation of the thread makes this command to
	 * return with Ocall command PTA_SCMI_OCALL_CMD_THREAD_READY.
	 */
	PTA_SCMI_CMD_OCALL_THREAD = 4,
};

/*
 * Capabilities
 */
enum pta_scmi_caps {
	PTA_SCMI_CAPS_NONE = 0,
	/*
	 * Supports command using SMT header protocol in shared memory
	 * buffers to carry SCMI protocol synchronisation information.
	 */
	PTA_SCMI_CAPS_SMT_HEADER = BIT32(0),
	/*
	 * Channel can use command PTA_SCMI_CMD_OCALL_THREAD to provision a
	 * TEE thread for SCMI message passing.
	 */
	PTA_SCMI_CAPS_OCALL_THREAD = BIT32(1),
};

#define PTA_SCMI_CAPS_VALID_MASK	(PTA_SCMI_CAPS_SMT_HEADER | \
					 PTA_SCMI_CAPS_OCALL_THREAD)

/*
 * enum optee_scmi_ocall_cmd
 * enum optee_scmi_ocall_reply
 *
 * These enumerates define the IDs used by REE/TEE to communicate in the
 * established REE/TEE Ocall thread context.
 *
 * At channel setup, we start from the REE: caller requests an Ocall context.
 *
 * 1. REE opens a session toward PTA SCMI. REE invokes PTA command
 *    PTA_SCMI_CMD_GET_CHANNEL to get a channel handler. Then REE invokes
 *    command PTA_SCMI_CAPS_OCALL_THREAD with an Ocall context. This is the
 *    initial invocation of the Ocall thread context. Any further error in
 *    the thread communication will close the thread and return from this
 *    initial invocation with an invocation error result.
 *
 * 2. Upon support of Ocall, OP-TEE creates an Ocall context and returns
 *    to REE with an Ocall, using Ocall command PTA_SCMI_OCALL_CMD_THREAD_READY.
 *
 * 3. REE can return from the Ocall with output param[0].value.a set to
 *    PTA_SCMI_OCALL_PROCESS_SMT_CHANNEL to have an SCMI message processed.
 *    In such case, OP-TEE processes the message and returns to REE with
 *    Ocall command PTA_SCMI_OCALL_CMD_THREAD_READY. The SCMI response is in
 *    the shared memory buffer.
 *
 * 4. Alternatively REE can return from the Ocall with output param[0].value.a
 *    set to PTA_SCMI_OCALL_CLOSE_THREAD. This requests OP-TEE to terminate the
 *    Ocall release resource and return from initial command invocation at [1]
 *    and REE can close the TEE session.
 *
 * At anytime, if an error is reported by Ocall commands and replies, OP-TEE
 * PTA SCMI will release the Ocall thread context and return from initial
 * invocation at 1. PTA_SCMI_OCALL_ERROR is used in Ocall return to
 * force an error report.
 *
 * At channel setup, REE driver executes steps 1. and 2.
 * When a REE agent wants to post an SCMI message, agent goes through step 3.
 * At channel release, REE driver executes step 4.
 */

enum optee_scmi_ocall_cmd {
	PTA_SCMI_OCALL_CMD_THREAD_READY = 0,
};

enum optee_scmi_ocall_reply {
	PTA_SCMI_OCALL_ERROR = 0,
	PTA_SCMI_OCALL_CLOSE_THREAD = 1,
	PTA_SCMI_OCALL_PROCESS_SMT_CHANNEL = 2,
};
#endif /* SCMI_PTA_SCMI_CLIENT_H */
