/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2021, Linaro Limited
 */
#ifndef PTA_SCMI_CLIENT_H
#define PTA_SCMI_CLIENT_H

#define PTA_SCMI_UUID { 0xa8cfe406, 0xd4f5, 0x4a2e, \
		{ 0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0x99 } }

#define PTA_SCMI_NAME "PTA-SCMI"

/*
 * PTA_SCMI_CMD_CAPABILITIES - Get channel capabilities
 *
 * [out]    value[0].a: Capabilities bit mask (PTA_SCMI_CAPS_*)
 * [out]    value[0].b: Extended capabilities or 0
 */
#define PTA_SCMI_CMD_CAPABILITIES	0

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
#define PTA_SCMI_CMD_PROCESS_SMT_CHANNEL	1

/*
 * PTA_SCMI_CMD_PROCESS_SMT_CHANNEL_MESSAGE - Process SCMI message in
 *				SMT buffer pointed by memref parameters
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
#define PTA_SCMI_CMD_PROCESS_SMT_CHANNEL_MESSAGE	2

/*
 * PTA_SCMI_CMD_GET_CHANNEL_HANDLE - Get handle for an SCMI channel
 *
 * Get a handle for the SCMI channel. This handle value is to be passed
 * as argument to some commands as PTA_SCMI_CMD_PROCESS_*.
 *
 * [in]     value[0].a: Channel identifier or 0 if no assigned ID
 * [in]     value[0].b: Requested capabilities mask (PTA_SCMI_CAPS_*)
 * [out]    value[0].a: Returned channel handle
 */
#define PTA_SCMI_CMD_GET_CHANNEL_HANDLE		3

/*
 * Capabilities
 */

/* Channel supports shared memory using the SMT header protocol */
#define PTA_SCMI_CAPS_SMT_HEADER			BIT32(0)

#endif /* SCMI_PTA_SCMI_CLIENT_H */
