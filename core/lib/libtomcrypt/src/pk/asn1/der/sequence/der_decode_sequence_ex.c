/*
 * Copyright (c) 2001-2007, Tom St Denis
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
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
#include <stdarg.h>


/**
  @file der_decode_sequence_ex.c
  ASN.1 DER, decode a SEQUENCE, Tom St Denis
*/

#ifdef LTC_DER

/**
   Decode a SEQUENCE
   @param in       The DER encoded input
   @param inlen    The size of the input
   @param list     The list of items to decode
   @param outlen   The number of items in the list
   @param ordered  Search an unordeded or ordered list
   @return CRYPT_OK on success
*/
int der_decode_sequence_ex(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *list,     unsigned long  outlen, int ordered)
{
   int           err, i;
   ltc_asn1_type type;
   unsigned long size, x, y, z, blksize;
   void          *data;

   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(list != NULL);

   /* get blk size */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* sequence type? We allow 0x30 SEQUENCE and 0x31 SET since fundamentally they're the same structure */
   x = 0;
   if (in[x] != 0x30 && in[x] != 0x31) {
      return CRYPT_INVALID_PACKET;
   }
   ++x;

   /* check if the msb is set, which signals that the
    * 7 lsb bits represent the number of bytes of the length
    */
   if (in[x] < 128) {
      blksize = in[x++];
   } else {
      if (in[x] < 0x81 || in[x] > 0x83) {
         return CRYPT_INVALID_PACKET;
      }
      y = in[x++] & 0x7F;

      /* would reading the len bytes overrun? */
      if (x + y > inlen) {
         return CRYPT_INVALID_PACKET;
      }

      /* read len */
      blksize = 0;
      while (y--) {
          blksize = (blksize << 8) | (unsigned long)in[x++];
      }
  }

  /* would this blksize overflow? */
  if (x + blksize > inlen) {
     return CRYPT_INVALID_PACKET;
  }

   /* mark all as unused */
   for (i = 0; i < (int)outlen; i++) {
       list[i].used = 0;
   }

  /* ok read data */
   inlen = blksize;
   for (i = 0; i < (int)outlen; i++) {
       z    = 0;
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;
       if (!ordered && list[i].used == 1) { continue; }

       if (type == LTC_ASN1_EOL) {
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
               z = inlen;
               if ((err = der_decode_boolean(in + x, z, ((int *)data))) != CRYPT_OK) {
                   goto LBL_ERR;
               }
               if ((err = der_length_boolean(&z)) != CRYPT_OK) {
                   goto LBL_ERR;
                }
                break;

           case LTC_ASN1_INTEGER:
               z = inlen;
               if ((err = der_decode_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered) {  continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_integer(data, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SHORT_INTEGER:
               z = inlen;
               if ((err = der_decode_short_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_short_integer(((unsigned long*)data)[0], &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }

               break;

           case LTC_ASN1_BIT_STRING:
               z = inlen;
               if ((err = der_decode_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_RAW_BIT_STRING:
               z = inlen;
               if ((err = der_decode_raw_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_OCTET_STRING:
               z = inlen;
               if ((err = der_decode_octet_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_octet_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_NULL:
               if (inlen < 2 || in[x] != 0x05 || in[x+1] != 0x00) {
                  if (!ordered) { continue; }
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }
               z = 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               z = inlen;
               if ((err = der_decode_object_identifier(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_object_identifier(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_TELETEX_STRING:
               z = inlen;
               if ((err = der_decode_teletex_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_teletex_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_IA5_STRING:
               z = inlen;
               if ((err = der_decode_ia5_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_ia5_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;


           case LTC_ASN1_PRINTABLE_STRING:
               z = inlen;
               if ((err = der_decode_printable_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_printable_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTF8_STRING:
               z = inlen;
               if ((err = der_decode_utf8_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_utf8_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTCTIME:
               z = inlen;
               if ((err = der_decode_utctime(in + x, &z, data)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SET:
               z = inlen;
               if ((err = der_decode_set(in + x, z, data, size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               /* detect if we have the right type */
               if ((type == LTC_ASN1_SETOF && (in[x] & 0x3F) != 0x31) || (type == LTC_ASN1_SEQUENCE && (in[x] & 0x3F) != 0x30)) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }

               z = inlen;
               if ((err = der_decode_sequence(in + x, z, data, size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;


           case LTC_ASN1_CHOICE:
               z = inlen;
               if ((err = der_decode_choice(in + x, &z, data, size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CONSTRUCTED:
           case LTC_ASN1_CONTEXT_SPECIFIC:
           case LTC_ASN1_EOL:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
           default:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
       x           += z;
       inlen       -= z;
       list[i].used = 1;
       if (!ordered) {
          /* restart the decoder */
          i = -1;
       }
   }

   for (i = 0; i < (int)outlen; i++) {
      if (list[i].used == 0) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
      }
   }
   err = CRYPT_OK;

LBL_ERR:
   return err;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
