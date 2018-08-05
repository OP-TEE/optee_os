/*
 * Copyright (C) 2017 GlobalLogic
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
  @file der_length_long_integer.c
  ASN.1 DER, get length of encoding, Tom St Denis
*/


#ifdef LTC_DER
/**
  Gets length of DER encoding of long integer num
  @param num    The long integer to get the size of
  @param outlen [out] The length of the DER encoding for the given long integer
  @return CRYPT_OK if successful
*/
int der_length_long_integer(unsigned long num, unsigned long *outlen)
{
   unsigned long z, y, len;

   LTC_ARGCHK(outlen  != NULL);

   /* get the number of bytes */
   z = 0;
   y = num;
   while (y) {
     ++z;
     y >>= 8;
   }

   /* handle zero */
   if (z == 0) {
      z = 1;
   }

   /* we need a 0x02 to indicate it's INTEGER */
   len = 1;

   /* length byte */
   ++len;

   /* bytes in value */
   len += z;

   /* see if msb is set */
   len += (num&(1UL<<((z<<3) - 1))) ? 1 : 0;

   /* return length */
   *outlen = len;

   return CRYPT_OK;
}

#endif
