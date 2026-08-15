/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PTA_QCOM_FUSE_H
#define __PTA_QCOM_FUSE_H

/*
 * Interface to the pseudo TA which exposes Qualcomm fuse state to
 * user-mode TAs that cannot access the fuse driver directly.
 */

#define PTA_QCOM_FUSE_UUID { 0x6b46384c, 0x4a3e, 0x4b9d, \
		{ 0xa8, 0x2f, 0x1c, 0x3d, 0xe5, 0x9f, 0xa2, 0x11 } }

/*
 * Query whether secure boot is enabled.
 *
 * [out] params[0].value.a:	1 if secure boot is enabled, 0 otherwise
 */
#define PTA_QCOM_FUSE_GET_SECBOOT_STATE		1

#define PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE	48

/*
 * Read the OEM root-of-trust digest.
 *
 * [out] params[0].memref:	buffer receiving the digest; must be at least
 *				PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE bytes
 */
#define PTA_QCOM_FUSE_GET_ROOT_OF_TRUST		2

/*
 * Read device-identity fields.
 *
 * [out] params[0].value.a:	OEM_ID
 * [out] params[0].value.b:	MODEL_ID
 * [out] params[1].value.a:	JTAG_ID (masked to authentication bits)
 * [out] params[1].value.b:	serial number
 */
#define PTA_QCOM_FUSE_GET_DEVICE_IDS		3

/*
 * Read the SOC hardware version family|device field.
 *
 * [out] params[0].value.a:	family|device number
 */
#define PTA_QCOM_FUSE_GET_SOC_HW_VERSION	4

/*
 * Read the firmware-segment hash digest size for a root_cert_sel index.
 *
 * [in]  params[0].value.a:	root_cert_sel (0-3)
 * [out] params[0].value.b:	digest size in bytes (32=SHA-256, 48=SHA-384)
 */
#define PTA_QCOM_FUSE_GET_SEGMENT_HASH_LEN	5

/*
 * Query whether Extended Key Usage enforcement is fused on.
 *
 * [out] params[0].value.a:	1 if EKU enforcement is enabled, 0 otherwise
 */
#define PTA_QCOM_FUSE_GET_EKU_ENFORCEMENT_EN	6

/*
 * Query the APPS serial-number binding override fuse.
 *
 * [out] params[0].value.a:	1 if the override is blown, 0 otherwise
 */
#define PTA_QCOM_FUSE_GET_USE_SERIAL_NUM	7

#endif /* __PTA_QCOM_FUSE_H */
