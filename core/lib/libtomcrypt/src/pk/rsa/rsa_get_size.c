/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_get_size.c
  Retrieve the size of an RSA key, Steffen Jaeckel.
*/

#ifdef LTC_MRSA

/**
  Retrieve the size in bytes of an RSA key.
  @param key      The RSA key
  @return The size in bytes of the RSA key or INT_MAX on error.
*/
int rsa_get_size(const rsa_key *key)
{
  int ret = INT_MAX;
  LTC_ARGCHK(key != NULL);

  if (key)
  {
    ret = mp_unsigned_bin_size(key->N);
  } /* if */

  return ret;
}

#endif
