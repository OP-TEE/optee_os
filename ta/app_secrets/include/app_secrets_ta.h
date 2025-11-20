/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Vaisala Oyj.
 */

#ifndef APP_SECRETS_TA_H
#define APP_SECRETS_TA_H

#define APP_SECRETS_TA_UUID \
	{ 0x5ca4d9d9, 0xdee4, 0x47f4, \
	  { 0x97, 0x7a, 0x7e, 0xad, 0xc0, 0x60, 0xe5, 0x2c } }

/*
 * Seal secret using hardware unique TA specific key
 *
 * [in]      memref[0]        Plain secret
 * [out]     memref[1]        Sealed secret datablob
 */
#define TA_APPSECRETS_CMD_SEAL_SECRET 0x0

/*
 * Unseal secret using hardware unique TA specific key
 *
 * [in]      memref[0]        Sealed secret datablob
 * [out]     memref[1]        Plain secret
 */
#define TA_APPSECRETS_CMD_UNSEAL_SECRET 0x1

#endif /* APP_SECRETS_TA_H */
