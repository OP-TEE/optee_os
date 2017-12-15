// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2001-2007, Tom St Denis
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file der_decode_choice.c
  ASN.1 DER, decode a CHOICE, Tom St Denis
*/

#ifdef LTC_DER

/**
   Decode a CHOICE
   @param in       The DER encoded input
   @param inlen    [in/out] The size of the input and resulting size of read type
   @param list     The list of items to decode
   @param outlen   The number of items in the list
   @return CRYPT_OK on success
*/
int der_decode_choice(const unsigned char *in,   unsigned long *inlen,
                            ltc_asn1_list *list, unsigned long  outlen)
{
   unsigned long size, x, z;
   void          *data;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);
   LTC_ARGCHK(list  != NULL);

   /* get blk size */
   if (*inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* set all of the "used" flags to zero */
   for (x = 0; x < outlen; x++) {
       list[x].used = 0;
   }

   /* now scan until we have a winner */
   for (x = 0; x < outlen; x++) {
       size = list[x].size;
       data = list[x].data;

       switch (list[x].type) {
           case LTC_ASN1_BOOLEAN:
               if (der_decode_boolean(in, *inlen, data) == CRYPT_OK) {
                  if (der_length_boolean(&z) == CRYPT_OK) {
                      list[x].used = 1;
                      *inlen       = z;
                      return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_INTEGER:
               if (der_decode_integer(in, *inlen, data) == CRYPT_OK) {
                  if (der_length_integer(data, &z) == CRYPT_OK) {
                      list[x].used = 1;
                      *inlen       = z;
                      return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_SHORT_INTEGER:
               if (der_decode_short_integer(in, *inlen, data) == CRYPT_OK) {
                  if (der_length_short_integer(size, &z) == CRYPT_OK) {
                      list[x].used = 1;
                      *inlen       = z;
                      return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_BIT_STRING:
               if (der_decode_bit_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_bit_string(size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_RAW_BIT_STRING:
               if (der_decode_raw_bit_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_bit_string(size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_OCTET_STRING:
               if (der_decode_octet_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_octet_string(size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_NULL:
               if (*inlen == 2 && in[x] == 0x05 && in[x+1] == 0x00) {
                  *inlen = 2;
                  list[x].used   = 1;
                  return CRYPT_OK;
               }
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               if (der_decode_object_identifier(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_object_identifier(data, size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_TELETEX_STRING:
               if (der_decode_teletex_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_teletex_string(data, size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_IA5_STRING:
               if (der_decode_ia5_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_ia5_string(data, size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_PRINTABLE_STRING:
               if (der_decode_printable_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_printable_string(data, size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_UTF8_STRING:
               if (der_decode_utf8_string(in, *inlen, data, &size) == CRYPT_OK) {
                  if (der_length_utf8_string(data, size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     list[x].size = size;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_UTCTIME:
               z = *inlen;
               if (der_decode_utctime(in, &z, data) == CRYPT_OK) {
                  list[x].used = 1;
                  *inlen       = z;
                  return CRYPT_OK;
               }
               break;

           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               if (der_decode_sequence(in, *inlen, data, size) == CRYPT_OK) {
                  if (der_length_sequence(data, size, &z) == CRYPT_OK) {
                     list[x].used = 1;
                     *inlen       = z;
                     return CRYPT_OK;
                  }
               }
               break;

           case LTC_ASN1_CHOICE:
           case LTC_ASN1_CONSTRUCTED:
           case LTC_ASN1_CONTEXT_SPECIFIC:
           case LTC_ASN1_EOL:
               return CRYPT_INVALID_ARG;
           default:
               return CRYPT_INVALID_ARG;
       }
   }

   return CRYPT_INVALID_PACKET;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
