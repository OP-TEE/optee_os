/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_decode_boolean.c
  ASN.1 DER, decode a BOOLEAN, Tom St Denis
*/


#ifdef LTC_DER

/**
  Read a BOOLEAN
  @param in      The destination for the DER encoded BOOLEAN
  @param inlen   The size of the DER BOOLEAN
  @param out     [out]  The boolean to decode
  @return CRYPT_OK if successful
*/
int der_decode_boolean(const unsigned char *in, unsigned long inlen,
                                       int *out)
{
   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(out != NULL);

   if (inlen < 3 || in[0] != 0x01 || in[1] != 0x01 || (in[2] != 0x00 && in[2] != 0xFF)) {
      return CRYPT_INVALID_ARG;
   }

   *out = (in[2]==0xFF) ? 1 : 0;

   return CRYPT_OK;
}

#endif
