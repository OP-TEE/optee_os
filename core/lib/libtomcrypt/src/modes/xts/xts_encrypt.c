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
  Source donated by Elliptic Semiconductor Inc (www.ellipticsemi.com) to the LibTom Projects
*/

#ifdef LTC_XTS_MODE

static int tweak_crypt(const unsigned char *P, unsigned char *C, unsigned char *T, symmetric_xts *xts)
{
   unsigned long x;
   int err;

   /* tweak encrypt block i */
#ifdef LTC_FAST
   for (x = 0; x < 16; x += sizeof(LTC_FAST_TYPE)) {
      *((LTC_FAST_TYPE*)&C[x]) = *((LTC_FAST_TYPE*)&P[x]) ^ *((LTC_FAST_TYPE*)&T[x]);
   }
#else
   for (x = 0; x < 16; x++) {
      C[x] = P[x] ^ T[x];
   }
#endif
     
   if ((err = cipher_descriptor[xts->cipher]->ecb_encrypt(C, C, &xts->key1)) != CRYPT_OK) {
      return err;
   }

#ifdef LTC_FAST
   for (x = 0; x < 16; x += sizeof(LTC_FAST_TYPE)) {
      *((LTC_FAST_TYPE*)&C[x]) ^= *((LTC_FAST_TYPE*)&T[x]);
   }
#else
   for (x = 0; x < 16; x++) {
       C[x] = C[x] ^ T[x];
   }
#endif

   /* LFSR the tweak */
   xts_mult_x(T);

   return CRYPT_OK;
}   

/** XTS Encryption
  @param pt     [in]  Plaintext
  @param ptlen  Length of plaintext (and ciphertext)
  @param ct     [out] Ciphertext
  @param tweak  [in] The 128--bit encryption tweak (e.g. sector number)
  @param xts    The XTS structure
  Returns CRYPT_OK upon success
*/
int xts_encrypt(const unsigned char *pt, unsigned long ptlen, unsigned char *ct, unsigned char *tweak,
         symmetric_xts *xts)
{
   const struct ltc_cipher_descriptor *desc;
   unsigned char PP[16], CC[16], T[16];
   unsigned long i, m, mo, lim;
   int           err;

   /* check inputs */
   LTC_ARGCHK(pt    != NULL);
   LTC_ARGCHK(ct    != NULL);
   LTC_ARGCHK(tweak != NULL);
   LTC_ARGCHK(xts   != NULL);

   /* check if valid */
   if ((err = cipher_is_valid(xts->cipher)) != CRYPT_OK) {
      return err;
   }

   /* get number of blocks */
   m  = ptlen >> 4;
   mo = ptlen & 15;

   /* must have at least one full block */
   if (m == 0) {
      return CRYPT_INVALID_ARG;
   }

   if (mo == 0) {
      lim = m;
   } else {
      lim = m - 1;
   }

   desc = cipher_descriptor[xts->cipher];

   if (desc->accel_xts_encrypt && lim > 0) {

      /* use accelerated encryption for whole blocks */
      if ((err = desc->accel_xts_encrypt(pt, ct, lim, tweak, &xts->key1,
					 &xts->key2) != CRYPT_OK)) {
	 return err;
      }
      ct += lim * 16;
      pt += lim * 16;

      /* tweak is encrypted on output */
      XMEMCPY(T, tweak, sizeof(T));
   } else {

      /* encrypt the tweak */
      if ((err = desc->ecb_encrypt(tweak, T, &xts->key2)) != CRYPT_OK) {
	 return err;
      }

      for (i = 0; i < lim; i++) {
         if ((err = tweak_crypt(pt, ct, T, xts)) != CRYPT_OK) {
            return err;
         }
         ct += 16;
         pt += 16;
      }
   }

   /* if ptlen not divide 16 then */
   if (mo > 0) {
      /* CC = tweak encrypt block m-1 */
      if ((err = tweak_crypt(pt, CC, T, xts)) != CRYPT_OK) {
         return err;
      }

      /* Cm = first ptlen % 16 bytes of CC */
      for (i = 0; i < mo; i++) {
          PP[i] = pt[16+i];
          ct[16+i] = CC[i];
      }

      for (; i < 16; i++) {
          PP[i] = CC[i];
      }

      /* Cm-1 = Tweak encrypt PP */
      if ((err = tweak_crypt(PP, ct, T, xts)) != CRYPT_OK) {
         return err;
      }
   }

   /* Decrypt the tweak back */
   if ((err = cipher_descriptor[xts->cipher]->ecb_decrypt(T, tweak, &xts->key2)) != CRYPT_OK) {
      return err;
   }

   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/modes/xts/xts_encrypt.c,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2007/05/12 14:05:56 $ */
