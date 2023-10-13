/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, The ChromiumOS Authors
 */

#ifndef __PTA_WIDEVINE_H
#define __PTA_WIDEVINE_H

/*
 * Interface to the widevine pseudo-TA, which is used for passing parameters
 * for widevine TA.
 */
#define PTA_WIDEVINE_UUID                                              \
	{                                                              \
		0x721f4da9, 0xda05, 0x40d4,                            \
		{                                                      \
			0xa1, 0xa3, 0x83, 0x77, 0xc1, 0xe0, 0x8b, 0x0a \
		}                                                      \
	}

/*
 * PTA_WIDEVINE_GET_TPM_PUBKEY - Get Widevine TPM public key
 * PTA_WIDEVINE_GET_WIDEVINE_PRIVKEY - Get Widevine private key
 *
 * [out]     memref[0]        Retrieved key data
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect parameters
 * TEE_ERROR_SHORT_BUFFER - Output buffer size is too small
 * TEE_ERROR_NO_DATA - Requested data not available
 */
#define PTA_WIDEVINE_GET_TPM_PUBKEY 0
#define PTA_WIDEVINE_GET_WIDEVINE_PRIVKEY 1

#endif /* __PTA_WIDEVINE_H */
