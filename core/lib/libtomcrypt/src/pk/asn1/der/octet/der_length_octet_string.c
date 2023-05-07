/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_length_octet_string.c
  ASN.1 DER, get length of OCTET STRING, Tom St Denis
*/

#ifdef LTC_DER
/**
  Gets length of DER encoding of OCTET STRING
  @param noctets  The number of octets in the string to encode
  @param outlen   [out] The length of the DER encoding for the given string
  @return CRYPT_OK if successful
*/
int der_length_octet_string(unsigned long noctets, unsigned long *outlen)
{
   unsigned long x;
   int err;

   LTC_ARGCHK(outlen != NULL);

   if ((err = der_length_asn1_length(noctets, &x)) != CRYPT_OK) {
      return err;
   }
   *outlen = 1 + x + noctets;

   return CRYPT_OK;
}

#endif

