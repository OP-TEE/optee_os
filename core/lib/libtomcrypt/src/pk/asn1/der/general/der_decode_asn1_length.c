/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_decode_asn1_length.c
  ASN.1 DER, decode the ASN.1 Length field, Steffen Jaeckel
*/

#ifdef LTC_DER
/**
  Decode the ASN.1 Length field
  @param in       Where to read the length field from
  @param inlen    [in/out] The size of in available/read
  @param outlen   [out] The decoded ASN.1 length
  @return CRYPT_OK if successful
*/
int der_decode_asn1_length(const unsigned char *in, unsigned long *inlen, unsigned long *outlen)
{
   unsigned long real_len, decoded_len, offset, i;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);

   if (*inlen < 1) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   real_len = in[0];

   if (real_len < 128) {
      decoded_len = real_len;
      offset = 1;
   } else {
      real_len &= 0x7F;
      if (real_len == 0) {
         return CRYPT_PK_ASN1_ERROR;
      }
      if (real_len > sizeof(decoded_len)) {
         return CRYPT_OVERFLOW;
      }
      if (real_len > (*inlen - 1)) {
         return CRYPT_BUFFER_OVERFLOW;
      }
      decoded_len = 0;
      offset = 1 + real_len;
      for (i = 0; i < real_len; i++) {
         decoded_len = (decoded_len << 8) | in[1 + i];
      }
   }

   if (outlen != NULL) *outlen = decoded_len;
   if (decoded_len > (*inlen - offset)) return CRYPT_OVERFLOW;
   *inlen = offset;

   return CRYPT_OK;
}

#endif
