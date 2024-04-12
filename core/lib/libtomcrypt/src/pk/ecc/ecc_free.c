/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ecc_free.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Free an ECC key from memory
  @param key   The key you wish to free
*/
void ecc_free(ecc_key *key)
{
   LTC_ARGCHKVD(key != NULL);

   mp_cleanup_multi(&key->dp.prime, &key->dp.order,
                    &key->dp.A, &key->dp.B,
                    &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                    &key->pubkey.x, &key->pubkey.y, &key->pubkey.z,
                    &key->k, NULL);
}

#endif
