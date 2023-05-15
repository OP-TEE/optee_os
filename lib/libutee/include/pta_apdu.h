/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2021, Foundries Limited
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef __PTA_APDU_H
#define __PTA_APDU_H

#define PTA_APDU_UUID { 0x3f3eb880, 0x3639, 0x11ec, \
			{ 0x9b, 0x9d, 0x0f, 0x3f, 0xc9, 0x46, 0x8f, 0x50 } }

/*
 * ADPU based communication with the Secure Element
 *
 * [in]  value[0].a           Use APDU TXRX hints: PTA_APDU_TXRX_CASE_*
 * [in]  memref[1].buffer     APDU header.
 * [in]  memref[1].size       APDU header length.
 * [in]  memref[2].buffer     request (APDU raw frame).
 * [in]  memref[2].size       request length.
 * [out] memref[3].buffer     response (APDU raw frame).
 * [out] memref[3].size       response length.
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_NOT_IMPLEMENTED - Invoke command not implemented
 * TEE_ERROR_GENERIC - Invoke command failure
 */
#define PTA_CMD_TXRX_APDU_RAW_FRAME		0

/*
 * Type identifier for the APDU message as described by Smart Card Standard
 * ISO7816-4 about ADPU message bodies decoding convention:
 *
 * https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/#chap5_3_2
 */
#define PTA_APDU_TXRX_CASE_NO_HINT	0
#define PTA_APDU_TXRX_CASE_1		1
#define PTA_APDU_TXRX_CASE_2		2
#define PTA_APDU_TXRX_CASE_2E		3
#define PTA_APDU_TXRX_CASE_3		4
#define PTA_APDU_TXRX_CASE_3E		5
#define PTA_APDU_TXRX_CASE_4		6
#define PTA_APDU_TXRX_CASE_4E		7

#endif /* __PTA_APDU_H */
