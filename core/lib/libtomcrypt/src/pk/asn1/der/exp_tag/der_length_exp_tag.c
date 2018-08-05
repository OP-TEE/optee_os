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
  @file der_length_exp_tag.c
  ASN.1 DER, get length of explicit tag
*/

#ifdef LTC_DER

/**
   Get the length of a DER explicit tag
   @param tag    The structure, which contain tag value and type for tagging.
   @param outlen [out] The length required in octets to store it
   @return CRYPT_OK on success
*/
int der_length_exp_tag(ltc_exp_tag *tag, unsigned long *outlen, unsigned long *payloadlen)
{
   int           err;
   ltc_asn1_type type;
   unsigned long size, x, y, z, tag_val;
   void          *data;

   LTC_ARGCHK(tag    != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* get size of output that will be required */
   y = 0;

   /* force to 32 bits */
   tag_val = tag->tag & 0xFFFFFFFFUL;
   type = tag->list->type;
   size = tag->list->size;
   data = tag->list->data;

   switch (type) {
      case LTC_ASN1_BOOLEAN:
         if ((err = der_length_boolean(&x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_INTEGER:
         if ((err = der_length_integer(data, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_SHORT_INTEGER:
         if ((err = der_length_short_integer(*((unsigned long *)data), &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_LONG_INTEGER:
         if ((err = der_length_long_integer(*((unsigned long *)data), &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_BIT_STRING:
      case LTC_ASN1_RAW_BIT_STRING:
         if ((err = der_length_bit_string(size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_OCTET_STRING:
         if ((err = der_length_octet_string(size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_NULL:
         y += 2;
         break;

      case LTC_ASN1_OBJECT_IDENTIFIER:
         if ((err = der_length_object_identifier(data, size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_IA5_STRING:
         if ((err = der_length_ia5_string(data, size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_TELETEX_STRING:
         if ((err = der_length_teletex_string(data, size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_PRINTABLE_STRING:
         if ((err = der_length_printable_string(data, size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_UTCTIME:
         if ((err = der_length_utctime(data, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_GENERALIZEDTIME:
         if ((err = der_length_generalizedtime(data, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_UTF8_STRING:
         if ((err = der_length_utf8_string(data, size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_SET:
      case LTC_ASN1_SETOF:
      case LTC_ASN1_SEQUENCE:
         if ((err = der_length_sequence(data, size, &x)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         y += x;
         break;

      case LTC_ASN1_EXP_TAG:
          if ((err = der_length_exp_tag(data, &x, NULL)) != CRYPT_OK) {
             goto LBL_ERR;
          }
          y += x;
          break;

      case LTC_ASN1_CHOICE:
      case LTC_ASN1_CONSTRUCTED:
      case LTC_ASN1_CONTEXT_SPECIFIC:
      case LTC_ASN1_EOL:
      default:
         err = CRYPT_INVALID_ARG;
         goto LBL_ERR;
   }

   /* calc header size */
   z = y;
   if (y < 128) {
      y += 2;
   } else if (y < 256) {
      /* 0x30 0x81 LL */
      y += 3;
   } else if (y < 65536UL) {
      /* 0x30 0x82 LL LL */
      y += 4;
   } else if (y < 16777216UL) {
      /* 0x30 0x83 LL LL LL */
      y += 5;
   } else {
      err = CRYPT_INVALID_ARG;
      goto LBL_ERR;
   }

   /* calc high-tag-number form */
   if (tag_val > 30) {
      do {
         tag_val >>= 7;
         y++;
	   } while (tag_val);
   }

   /* store size */
   if (payloadlen) *payloadlen = z;
   *outlen = y;
   err     = CRYPT_OK;

LBL_ERR:
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
