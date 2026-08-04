/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PTA_QCOM_ICE_H
#define __PTA_QCOM_ICE_H

/*
 * Qualcomm ICE PTA - Filesystem Encryption using the Inline Crypto Engine
 * Provides hardware key configuration for ICE-accelerated storage encryption.
 * Storage-controller agnostic: caters to ICE blocks on different storage
 * controllers (eMMC/SDCC, UFS, ...).
 * UUID: {29e87b9e-012a-4878-a1e1-a1b90a215b16}
 */
#define PTA_QCOM_ICE_UUID \
	{ 0x29e87b9e, 0x012a, 0x4878, \
		{ 0xa1, 0xe1, 0xa1, 0xb9, 0x0a, 0x21, 0x5b, 0x16 } }

/*
 * Invalidate ICE key slot - overwrite key registers with random data
 * [in]  params[0].value.a           Key slot index (0..ICE_MAX_KEY_IDX-1)
 */
#define PTA_CMD_ICE_INVALIDATE_KEY    0

/*
 * Set ICE key slot with raw key material and full configuration
 * [in]  params[0].value.a           Key slot index (0..ICE_MAX_KEY_IDX-1)
 * [in]  params[0].value.b           Cap index (ice_capability_index_type)
 * [in]  params[1].value.a           Data unit size (ice_data_unit_type)
 * [in]  params[2].memref.buffer     Key data: key bytes followed by salt bytes
 *                                   XTS-128: 16B key + 16B salt = 32 bytes
 *                                   XTS-256: 32B key + 32B salt = 64 bytes
 *                                   CBC-128: 16B key
 *                                   CBC-256: 32B key
 * [in]  params[2].memref.size       Total key data size
 */
#define PTA_CMD_ICE_SET_CONFIG_KEY    1

#endif /* __PTA_QCOM_ICE_H */
