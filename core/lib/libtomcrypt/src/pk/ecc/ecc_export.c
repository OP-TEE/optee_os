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

/* Implements ECC over Z/pZ for curve y^2 = x^3 - 3x + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */
#include "tomcrypt.h"

/**
  @file ecc_export.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/**
  Export an ECC key as a binary packet
  @param out     [out] Destination for the key
  @param outlen  [in/out] Max size and resulting size of the exported key
  @param type    The type of key you want to export (PK_PRIVATE or PK_PUBLIC)
  @param key     The key to export
  @return CRYPT_OK if successful
*/
int ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key)
{
   int           err;
   unsigned char flags[1];
   unsigned long key_size;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
   
   /* type valid? */
   if (key->type != PK_PRIVATE && type == PK_PRIVATE) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   if (ltc_ecc_is_valid_idx(key->idx) == 0) {
      return CRYPT_INVALID_ARG;
   }

   /* we store the NIST byte size */
   key_size = key->dp->size;

   if (type == PK_PRIVATE) {
       flags[0] = 1;
       err = der_encode_sequence_multi(out, outlen,
                                 LTC_ASN1_BIT_STRING,      1UL, flags,
                                 LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                 LTC_ASN1_INTEGER,         1UL, key->pubkey.x,
                                 LTC_ASN1_INTEGER,         1UL, key->pubkey.y,
                                 LTC_ASN1_INTEGER,         1UL, key->k,
                                 LTC_ASN1_EOL,             0UL, NULL);
   } else {
       flags[0] = 0;
       err = der_encode_sequence_multi(out, outlen,
                                 LTC_ASN1_BIT_STRING,      1UL, flags,
                                 LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                 LTC_ASN1_INTEGER,         1UL, key->pubkey.x,
                                 LTC_ASN1_INTEGER,         1UL, key->pubkey.y,
                                 LTC_ASN1_EOL,             0UL, NULL);
   }

   return err;
}

#endif
/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_export.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2007/05/12 14:32:35 $ */
