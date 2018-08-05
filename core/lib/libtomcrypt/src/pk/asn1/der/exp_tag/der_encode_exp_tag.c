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
  @file der_encode_exp_tag.c
  ASN.1 DER, encode a EXPLICIT TAG
*/


#ifdef LTC_DER

/**
  Store an EXPLICIT TAG
  @param tag          Explicit tag structure to encode
  @param out          The destination of the DER encoding of the explicit tag
  @param outlen       [in/out] The length of the DER encoding
  @return CRYPT_OK if successful
*/
int der_encode_exp_tag(ltc_exp_tag *tag_st, unsigned char *out, unsigned long *outlen)
{
   int           err;
   ltc_asn1_type type;
   unsigned long size, x, y, z, tag_val;
   void          *data;

   LTC_ARGCHK(tag_st    != NULL);
   LTC_ARGCHK(out     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* get size of output that will be required */
   y = 0; z = 0;
   if ((err = der_length_exp_tag(tag_st, &y, &z)) != CRYPT_OK) return CRYPT_INVALID_ARG;

   /* too big ? */
   if (*outlen < y) {
      *outlen = y;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* force to 32 bits */
   tag_val = tag_st->tag & 0xFFFFFFFFUL;

   /* store header */
   x = 0;
   if (tag_val <= 30) {
	   /* calc low-tag-number form */
	   out[x++] = 0xA0 ^ tag_val;
   } else {
      /* calc high-tag-number form */
      out[x] = 0xBF;
      y = 0; /* number of octets for tag */
      do {
	     tag_val >>= 7;
	     ++y;
      } while (tag_val);
      tag_val = tag_st->tag;
      x += y;
      out[x--] = (tag_val & 0x7F); /* last octet with setting 8 bit to 0 */
      while (x > 0) {
         tag_val >>= 7;
         out[x--] = 0x80 ^ (tag_val & 0x7F); /* set 8 bit to 1 and 7-bit mask */
      }
      x += y + 1;
   }

   if (z < 128) {
      out[x++] = (unsigned char)z;
   } else if (z < 256) {
      out[x++] = 0x81;
      out[x++] = (unsigned char)z;
   } else if (z < 65536UL) {
      out[x++] = 0x82;
      out[x++] = (unsigned char)((z>>8UL)&255);
      out[x++] = (unsigned char)(z&255);
   } else if (z < 16777216UL) {
      out[x++] = 0x83;
      out[x++] = (unsigned char)((z>>16UL)&255);
      out[x++] = (unsigned char)((z>>8UL)&255);
      out[x++] = (unsigned char)(z&255);
   }

   /* store data */
   *outlen -= x;
   type = tag_st->list->type;
   size = tag_st->list->size;
   data = tag_st->list->data;

   switch (type) {
      case LTC_ASN1_BOOLEAN:
         z = *outlen;
         if ((err = der_encode_boolean(*((int *)data), out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_INTEGER:
         z = *outlen;
         if ((err = der_encode_integer(data, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_SHORT_INTEGER:
         z = *outlen;
         if ((err = der_encode_short_integer(*((unsigned long*)data), out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_LONG_INTEGER:
         z = *outlen;
         if ((err = der_encode_long_integer(*((unsigned long*)data), out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_BIT_STRING:
         z = *outlen;
         if ((err = der_encode_bit_string(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_RAW_BIT_STRING:
         z = *outlen;
         if ((err = der_encode_raw_bit_string(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_OCTET_STRING:
         z = *outlen;
         if ((err = der_encode_octet_string(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_NULL:
         out[x] = 0x05;
         out[x+1] = 0x00;
         z = 2;
         break;

      case LTC_ASN1_OBJECT_IDENTIFIER:
         z = *outlen;
         if ((err = der_encode_object_identifier(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_IA5_STRING:
         z = *outlen;
         if ((err = der_encode_ia5_string(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_PRINTABLE_STRING:
         z = *outlen;
         if ((err = der_encode_printable_string(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_UTF8_STRING:
         z = *outlen;
         if ((err = der_encode_utf8_string(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_UTCTIME:
         z = *outlen;
         if ((err = der_encode_utctime(data, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_GENERALIZEDTIME:
         z = *outlen;
         if ((err = der_encode_generalizedtime(data, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_SET:
         z = *outlen;
         if ((err = der_encode_set(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_SETOF:
         z = *outlen;
         if ((err = der_encode_setof(data, size, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_SEQUENCE:
         z = *outlen;
         if ((err = der_encode_sequence_ex(data, size, out + x, &z, type)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_EXP_TAG:
         z = *outlen;
         if ((err = der_encode_exp_tag(data, out + x, &z)) != CRYPT_OK) {
            goto LBL_ERR;
         }
         break;

      case LTC_ASN1_CHOICE:
      case LTC_ASN1_CONSTRUCTED:
      case LTC_ASN1_CONTEXT_SPECIFIC:
      case LTC_ASN1_EOL:
      case LTC_ASN1_TELETEX_STRING:
      default:
         err = CRYPT_INVALID_ARG;
         goto LBL_ERR;
   }

   x       += z;
   *outlen -= z;
   *outlen = x;
   err = CRYPT_OK;

LBL_ERR:
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
