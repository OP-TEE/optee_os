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
#ifndef __CRYPTO_SE_H
#define __CRYPTO_SE_H

#include <tee_api_types.h>

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
