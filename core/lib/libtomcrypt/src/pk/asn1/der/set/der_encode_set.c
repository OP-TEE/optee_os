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
  @file der_encode_set.c
  ASN.1 DER, Encode a SET, Tom St Denis
*/

#ifdef LTC_DER

/* LTC define to ASN.1 TAG */
static int ltc_to_asn1(ltc_asn1_type v)
{
   switch (v) {
      case LTC_ASN1_BOOLEAN:                 return 0x01;
      case LTC_ASN1_INTEGER:
      case LTC_ASN1_SHORT_INTEGER:           return 0x02;
      case LTC_ASN1_RAW_BIT_STRING:
      case LTC_ASN1_BIT_STRING:              return 0x03;
      case LTC_ASN1_OCTET_STRING:            return 0x04;
      case LTC_ASN1_NULL:                    return 0x05;
      case LTC_ASN1_OBJECT_IDENTIFIER:       return 0x06;
      case LTC_ASN1_UTF8_STRING:             return 0x0C;
      case LTC_ASN1_PRINTABLE_STRING:        return 0x13;
      case LTC_ASN1_TELETEX_STRING:          return 0x14;
      case LTC_ASN1_IA5_STRING:              return 0x16;
      case LTC_ASN1_UTCTIME:                 return 0x17;
      case LTC_ASN1_SEQUENCE:                return 0x30;
      case LTC_ASN1_SET:
      case LTC_ASN1_SETOF:                   return 0x31;
      case LTC_ASN1_CHOICE:
      case LTC_ASN1_CONSTRUCTED:
      case LTC_ASN1_CONTEXT_SPECIFIC:
      case LTC_ASN1_EOL:                     return -1;
      default:                               return -1;
   }
   return -1;
}


static int qsort_helper(const void *a, const void *b)
{
   ltc_asn1_list *A = (ltc_asn1_list *)a, *B = (ltc_asn1_list *)b;
   int            r;

   r = ltc_to_asn1(A->type) - ltc_to_asn1(B->type);

   /* for QSORT the order is UNDEFINED if they are "equal" which means it is NOT DETERMINISTIC.  So we force it to be :-) */
   if (r == 0) {
      /* their order in the original list now determines the position */
      return A->used - B->used;
   } else {
      return r;
   }
}

/*
   Encode a SET type
   @param list      The list of items to encode
   @param inlen     The number of items in the list
   @param out       [out] The destination
   @param outlen    [in/out] The size of the output
   @return CRYPT_OK on success
*/
int der_encode_set(ltc_asn1_list *list, unsigned long inlen,
                   unsigned char *out,  unsigned long *outlen)
{
   ltc_asn1_list  *copy;
   unsigned long   x;
   int             err;

   /* make copy of list */
   copy = XCALLOC(inlen, sizeof(*copy));
   if (copy == NULL) {
      return CRYPT_MEM;
   }

   /* fill in used member with index so we can fully sort it */
   for (x = 0; x < inlen; x++) {
       copy[x]      = list[x];
       copy[x].used = x;
   }

   /* sort it by the "type" field */
   XQSORT(copy, inlen, sizeof(*copy), &qsort_helper);

   /* call der_encode_sequence_ex() */
   err = der_encode_sequence_ex(copy, inlen, out, outlen, LTC_ASN1_SET);

   /* free list */
   XFREE(copy);

   return err;
}


#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
