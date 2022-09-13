/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file base64_encode.c
  Compliant base64 encoder donated by Wayne Scott (wscott@bitmover.com)
  base64 URL Safe variant (RFC 4648 section 5) by Karel Miko
*/


#if defined(LTC_BASE64) || defined (LTC_BASE64_URL)

#if defined(LTC_BASE64)
static const char * const codes_base64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#endif /* LTC_BASE64 */

#if defined(LTC_BASE64_URL)
static const char * const codes_base64url =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
#endif /* LTC_BASE64_URL */

enum mode {
   nopad = 0,
   pad = 1,
   lf = 2,
   cr = 4,
   ssh = 8,
   crlf = lf | cr,
};

static int s_base64_encode_internal(const unsigned char *in,    unsigned long inlen,
                                                   char *out,   unsigned long *outlen,
                                    const          char *codes, unsigned int  mode)
{
   unsigned long i, len2, leven, linelen;
   char *p;

   LTC_ARGCHK(outlen != NULL);

   linelen = (mode & ssh) ? 72 : 64;

   /* valid output size ? */
   len2 = 4 * ((inlen + 2) / 3);
   if ((mode & crlf) == lf) {
      len2 += len2 / linelen;
   } else if ((mode & crlf) == crlf) {
      len2 += (len2 / linelen) * 2;
   }
   if (*outlen < len2 + 1) {
      *outlen = len2 + 1;
      return CRYPT_BUFFER_OVERFLOW;
   }

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(out != NULL);

   if ((void*)in == out) {
      return CRYPT_INVALID_ARG;
   }

   p = out;
   leven = 3*(inlen / 3);
   for (i = 0; i < leven; i += 3) {
       *p++ = codes[(in[0] >> 2) & 0x3F];
       *p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
       *p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
       *p++ = codes[in[2] & 0x3F];
       in += 3;
       if ((p - out) % linelen == 0) {
          if (mode & cr) *p++ = '\r';
          if (mode & lf) *p++ = '\n';
       }
   }
   /* Pad it if necessary...  */
   if (i < inlen) {
       unsigned a = in[0];
       unsigned b = (i+1 < inlen) ? in[1] : 0;

       *p++ = codes[(a >> 2) & 0x3F];
       *p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
       if (mode & pad) {
         *p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
         *p++ = '=';
       }
       else {
         if (i+1 < inlen) *p++ = codes[(((b & 0xf) << 2)) & 0x3F];
       }
   }

   /* append a NULL byte */
   *p = '\0';

   /* return ok */
   *outlen = (unsigned long)(p - out); /* the length without terminating NUL */
   return CRYPT_OK;
}

#if defined(LTC_BASE64)
/**
   base64 Encode a buffer (NUL terminated)
   @param in      The input buffer to encode
   @param inlen   The length of the input buffer
   @param out     [out] The destination of the base64 encoded data
   @param outlen  [in/out] The max size and resulting size
   @return CRYPT_OK if successful
*/
int base64_encode(const unsigned char *in,  unsigned long inlen,
                                 char *out, unsigned long *outlen)
{
    return s_base64_encode_internal(in, inlen, out, outlen, codes_base64, pad);
}

/**
   base64 Encode a buffer for PEM output
     (NUL terminated with line-break at 64 chars)
   @param in       The input buffer to encode
   @param inlen    The length of the input buffer
   @param out      [out] The destination of the base64 encoded data
   @param outlen   [in/out] The max size and resulting size
   @param flags    \ref base64_pem_flags
   @return CRYPT_OK if successful
*/
int base64_encode_pem(const unsigned char *in,  unsigned long inlen,
                                     char *out, unsigned long *outlen,
                            unsigned int  flags)
{
    int use_crlf = flags & BASE64_PEM_CRLF ? pad | crlf : pad | lf;
    int ssh_style = flags & BASE64_PEM_SSH ? ssh : 0;
    return s_base64_encode_internal(in, inlen, out, outlen, codes_base64, ssh_style | use_crlf);
}
#endif /* LTC_BASE64 */


#if defined(LTC_BASE64_URL)
/**
   base64 (URL Safe, RFC 4648 section 5) Encode a buffer (NUL terminated)
   @param in      The input buffer to encode
   @param inlen   The length of the input buffer
   @param out     [out] The destination of the base64 encoded data
   @param outlen  [in/out] The max size and resulting size
   @return CRYPT_OK if successful
*/
int base64url_encode(const unsigned char *in,  unsigned long inlen,
                                    char *out, unsigned long *outlen)
{
    return s_base64_encode_internal(in, inlen, out, outlen, codes_base64url, nopad);
}

int base64url_strict_encode(const unsigned char *in,  unsigned long inlen,
                                           char *out, unsigned long *outlen)
{
    return s_base64_encode_internal(in, inlen, out, outlen, codes_base64url, pad);
}
#endif /* LTC_BASE64_URL */

#endif

