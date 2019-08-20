// SPDX-License-Identifier: BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

/**
  @file ecc_ansi_x963_export.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/** ECC X9.63 (Sec. 4.3.6) uncompressed export
  @param key     Key to export
  @param out     [out] destination of export
  @param outlen  [in/out]  Length of destination and final output size
  Return CRYPT_OK on success
*/
int ecc_ansi_x963_export(const ecc_key *key, unsigned char *out, unsigned long *outlen)
{
   return ecc_get_key(out, outlen, PK_PUBLIC, key);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
