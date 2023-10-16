/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2021 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
 /*
  * This is the Cryptographic Secure Element API, part of the Cryptographic
  * Provider API.
  *
  * These requests shall be handled in the secure element normally placed on
  * a serial communication bus (SPI, I2C).
  */
#ifndef __CRYPTO_CRYPTO_SE_H
#define __CRYPTO_CRYPTO_SE_H

#include <tee_api_types.h>

/*
 * Type identifier for the APDU message as described by Smart Card Standard
 * ISO7816-4 about ADPU message bodies decoding convention:
 *
 * https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/#chap5_3_2
 */
enum crypto_apdu_type {
	CRYPTO_APDU_CASE_NO_HINT,
	CRYPTO_APDU_CASE_1,
	CRYPTO_APDU_CASE_2,
	CRYPTO_APDU_CASE_2E,
	CRYPTO_APDU_CASE_3,
	CRYPTO_APDU_CASE_3E,
	CRYPTO_APDU_CASE_4,
	CRYPTO_APDU_CASE_4E,
};

TEE_Result crypto_se_do_apdu(enum crypto_apdu_type type,
			     uint8_t *header, size_t hdr_len,
			     uint8_t *src_data, size_t src_len,
			     uint8_t *dst_data, size_t *dst_len);

/*
 * Enable Secure Channel Protocol 03 to communicate with the Secure Element.
 *
 * Since SCP03 uses symmetric encryption, this interface also allows the user to
 * attempt the rotation the keys stored in the Secure Element.
 *
 * https://globalplatform.org/wp-content/uploads/2014/07/GPC_2.3_D_SCP03_v1.1.2_PublicRelease.pdf
 */
TEE_Result crypto_se_enable_scp03(bool rotate_keys);
#endif
