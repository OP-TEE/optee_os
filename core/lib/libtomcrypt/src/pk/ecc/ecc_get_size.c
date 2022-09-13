/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ecc_get_size.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Get the size of an ECC key
  @param key    The key to get the size of
  @return The size (octets) of the key or INT_MAX on error
*/
int ecc_get_size(const ecc_key *key)
{
   if (key == NULL) {
      return INT_MAX;
   }
   return key->dp.size;
}

#endif
