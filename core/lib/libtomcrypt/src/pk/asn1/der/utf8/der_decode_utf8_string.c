/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_decode_utf8_string.c
  ASN.1 DER, encode a UTF8 STRING, Tom St Denis
*/


#ifdef LTC_DER

/**
  Decode a UTF8 STRING and recover an array of unicode characters.
  @param in      The DER encoded UTF8 STRING
  @param inlen   The size of the DER UTF8 STRING
  @param out     [out] The array of unicode characters (wchar_t*)
  @param outlen  [in/out] The number of unicode characters in the array
  @return CRYPT_OK if successful
*/
int der_decode_utf8_string(const unsigned char *in,  unsigned long inlen,
                                       wchar_t *out, unsigned long *outlen)
{
   wchar_t       tmp;
   unsigned long x, y, z, len;
   int err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* must have header at least */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* check for 0x0C */
   if ((in[0] & 0x1F) != 0x0C) {
      return CRYPT_INVALID_PACKET;
   }
   x = 1;

   /* get the length of the data */
   y = inlen - x;
   if ((err = der_decode_asn1_length(in + x, &y, &len)) != CRYPT_OK) {
      return err;
   }
   x += y;

   if (len > (inlen - x)) {
      return CRYPT_INVALID_PACKET;
   }

   /* proceed to recover unicode characters from utf8 data.
      for reference see Section 3 of RFC 3629:

        https://tools.ietf.org/html/rfc3629#section-3
    */
   for (y = 0; x < inlen; ) {
      /* read first byte */
      tmp = in[x++];

      /* a unicode character is recovered from a sequence of 1 to 4 utf8 bytes.
         the form of those bytes must match a row in the following table:

           0xxxxxxx
           110xxxxx 10xxxxxx
           1110xxxx 10xxxxxx 10xxxxxx
           11110xxx 10xxxxxx 10xxxxxx 10xxxxxx

         the number of leading ones in the first byte (0,2,3,4) determines the
         number of remaining bytes to read (0,1,2,3)
       */

      /* determine z, the number of leading ones.
         this is done by left-shifting tmp, which clears the ms-bits */
      for (z = 0; (tmp & 0x80) && (z <= 4); z++, tmp = (tmp << 1) & 0xFF);

      /* z should be in {0,2,3,4} */
      if (z == 1 || z > 4) {
         return CRYPT_INVALID_PACKET;
      }

      /* right-shift tmp to restore least-sig bits */
      tmp >>= z;

      /* now update z so it equals the number of additional bytes to read */
      if (z > 0) { --z; }

      if (x + z > inlen) {
         return CRYPT_INVALID_PACKET;
      }

      /* read remaining bytes */
      while (z-- != 0) {
         if ((in[x] & 0xC0) != 0x80) {
            return CRYPT_INVALID_PACKET;
         }
         tmp = (tmp << 6) | ((wchar_t)in[x++] & 0x3F);
      }

      if (y < *outlen) {
         out[y] = tmp;
      }
      y++;
   }
   if (y > *outlen) {
      err = CRYPT_BUFFER_OVERFLOW;
   } else {
      err = CRYPT_OK;
   }
   *outlen = y;

   return err;
}

#endif
