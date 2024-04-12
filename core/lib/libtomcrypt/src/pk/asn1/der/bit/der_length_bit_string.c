/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_length_bit_string.c
  ASN.1 DER, get length of BIT STRING, Tom St Denis
*/

#ifdef LTC_DER
/**
  Gets length of DER encoding of BIT STRING
  @param nbits  The number of bits in the string to encode
  @param outlen [out] The length of the DER encoding for the given string
  @return CRYPT_OK if successful
*/
int der_length_bit_string(unsigned long nbits, unsigned long *outlen)
{
   unsigned long nbytes, x;
   int err;

   LTC_ARGCHK(outlen != NULL);

   /* get the number of the bytes */
   nbytes = (nbits >> 3) + ((nbits & 7) ? 1 : 0) + 1;

   if ((err = der_length_asn1_length(nbytes, &x)) != CRYPT_OK) {
      return err;
   }
   *outlen = 1 + x + nbytes;

   return CRYPT_OK;
}

#endif

