/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_encode_ia5_string.c
  ASN.1 DER, encode a IA5 STRING, Tom St Denis
*/

#ifdef LTC_DER

/**
  Store an IA5 STRING
  @param in       The array of IA5 to store (one per char)
  @param inlen    The number of IA5 to store
  @param out      [out] The destination for the DER encoded IA5 STRING
  @param outlen   [in/out] The max size and resulting size of the DER IA5 STRING
  @return CRYPT_OK if successful
*/
int der_encode_ia5_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y, len;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* get the size */
   if ((err = der_length_ia5_string(in, inlen, &len)) != CRYPT_OK) {
      return err;
   }

   /* too big? */
   if (len > *outlen) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* encode the header+len */
   x = 0;
   out[x++] = 0x16;
   len = *outlen - x;
   if ((err = der_encode_asn1_length(inlen, out + x, &len)) != CRYPT_OK) {
      return err;
   }
   x += len;

   /* store octets */
   for (y = 0; y < inlen; y++) {
       out[x++] = der_ia5_char_encode(in[y]);
   }

   /* retun length */
   *outlen = x;

   return CRYPT_OK;
}

#endif
