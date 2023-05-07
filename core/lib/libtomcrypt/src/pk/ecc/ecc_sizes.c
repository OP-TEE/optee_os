/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ecc_sizes.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

void ecc_sizes(int *low, int *high)
{
  int i, size;
  void *prime;

  LTC_ARGCHKVD(low  != NULL);
  LTC_ARGCHKVD(high != NULL);

  *low = INT_MAX;
  *high = 0;

  if (mp_init(&prime) == CRYPT_OK) {
    for (i = 0; ltc_ecc_curves[i].prime != NULL; i++) {
       if (mp_read_radix(prime, ltc_ecc_curves[i].prime, 16) == CRYPT_OK) {
         size = mp_unsigned_bin_size(prime);
         if (size < *low)  *low  = size;
         if (size > *high) *high = size;
       }
    }
    mp_clear(prime);
  }
}

#endif
