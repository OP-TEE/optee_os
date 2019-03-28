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
   @file dsa_import.c
   DSA implementation, import a DSA key, Tom St Denis
*/

#ifdef LTC_MDSA

/**
   Import a DSA key 
   @param in       The binary packet to import from
   @param inlen    The length of the binary packet
   @param key      [out] Where to store the imported key
   @return CRYPT_OK if successful, upon error this function will free all allocated memory
*/
int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   int           err;
   unsigned long zero = 0;
   unsigned char* tmpbuf = NULL;
   unsigned char flags[1];

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if (mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* try to match the old libtomcrypt format */
   if ((err = der_decode_sequence_multi(in, inlen,
                                  LTC_ASN1_BIT_STRING, 1UL, flags,
                                  LTC_ASN1_EOL, 0UL, NULL)) == CRYPT_OK) {
       /* private key */
       if (flags[0]) {
           if ((err = der_decode_sequence_multi(in, inlen,
                                  LTC_ASN1_BIT_STRING,   1UL, flags,
                                  LTC_ASN1_INTEGER,      1UL, key->g,
                                  LTC_ASN1_INTEGER,      1UL, key->p,
                                  LTC_ASN1_INTEGER,      1UL, key->q,
                                  LTC_ASN1_INTEGER,      1UL, key->y,
                                  LTC_ASN1_INTEGER,      1UL, key->x,
                                  LTC_ASN1_EOL,          0UL, NULL)) != CRYPT_OK) {
               goto LBL_ERR;
           }
           key->type = PK_PRIVATE;
           goto LBL_OK;
       }
       /* public key */
       else {
           if ((err = der_decode_sequence_multi(in, inlen,
                                      LTC_ASN1_BIT_STRING,   1UL, flags,
                                      LTC_ASN1_INTEGER,      1UL, key->g,
                                      LTC_ASN1_INTEGER,      1UL, key->p,
                                      LTC_ASN1_INTEGER,      1UL, key->q,
                                      LTC_ASN1_INTEGER,      1UL, key->y,
                                      LTC_ASN1_EOL,          0UL, NULL)) != CRYPT_OK) {
               goto LBL_ERR;
           }
           key->type = PK_PUBLIC;
           goto LBL_OK;
       }
   }
   /* get key type */
   if ((err = der_decode_sequence_multi(in, inlen,
                          LTC_ASN1_SHORT_INTEGER, 1UL, &zero,
                          LTC_ASN1_INTEGER,      1UL, key->p,
                          LTC_ASN1_INTEGER,      1UL, key->q,
                          LTC_ASN1_INTEGER,      1UL, key->g,
                          LTC_ASN1_INTEGER,      1UL, key->y,
                          LTC_ASN1_INTEGER,      1UL, key->x,
                          LTC_ASN1_EOL,          0UL, NULL)) == CRYPT_OK) {

       key->type = PK_PRIVATE;
   } else { /* public */
      ltc_asn1_list params[3];
      unsigned long tmpbuf_len = inlen;

      LTC_SET_ASN1(params, 0, LTC_ASN1_INTEGER, key->p, 1UL);
      LTC_SET_ASN1(params, 1, LTC_ASN1_INTEGER, key->q, 1UL);
      LTC_SET_ASN1(params, 2, LTC_ASN1_INTEGER, key->g, 1UL);

      tmpbuf = XCALLOC(1, tmpbuf_len);
      if (tmpbuf == NULL) {
          err = CRYPT_MEM;
          goto LBL_ERR;
      }

      err = der_decode_subject_public_key_info(in, inlen,
        PKA_DSA, tmpbuf, &tmpbuf_len,
        LTC_ASN1_SEQUENCE, params, 3);
      if (err != CRYPT_OK) {
         XFREE(tmpbuf);
         goto LBL_ERR;
      }

      if ((err=der_decode_integer(tmpbuf, tmpbuf_len, key->y)) != CRYPT_OK) {
         XFREE(tmpbuf);
         goto LBL_ERR;
      }

      XFREE(tmpbuf);
      key->type = PK_PUBLIC;
  }

LBL_OK:
  key->qord = mp_unsigned_bin_size(key->q);

  if (key->qord >= LTC_MDSA_MAX_GROUP || key->qord <= 15 ||
      (unsigned long)key->qord >= mp_unsigned_bin_size(key->p) || (mp_unsigned_bin_size(key->p) - key->qord) >= LTC_MDSA_DELTA) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

  return CRYPT_OK;
LBL_ERR:
   mp_clear_multi(key->p, key->g, key->q, key->x, key->y, NULL);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/dsa/dsa_import.c,v $ */
/* $Revision: 1.14 $ */
/* $Date: 2007/05/12 14:32:35 $ */
