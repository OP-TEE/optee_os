/*
 * Copyright (C) 2018 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tomcrypt.h"

/**
  @file der_decode_long_integer.c
  ASN.1 DER, decode an integer, Tom St Denis
*/


#ifdef LTC_DER

/**
  Read a long integer
  @param in       The DER encoded data
  @param inlen    Size of data
  @param num      [out] The integer to decode
  @return CRYPT_OK if successful
*/
int der_decode_long_integer(const unsigned char *in, unsigned long inlen, unsigned long *num)
{
   unsigned long len, x, y;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(in     != NULL);

   /* check length */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* check header */
   x = 0;
   if ((in[x++] & 0x1F) != 0x02) {
      return CRYPT_INVALID_PACKET;
   }

   /* get the packet len */
   len = in[x++];

   if (x + len > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* read number */
   y = 0;
   while (len--) {
      y = (y<<8) | (unsigned long)in[x++];
   }
   *num = y;

   return CRYPT_OK;

}

#endif
