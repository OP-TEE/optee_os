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

static int tweak_uncrypt(const unsigned char *C, unsigned char *P, unsigned char *T, symmetric_xts *xts)
{
   unsigned long x;
   int err;

   /* tweak encrypt block i */
#ifdef LTC_FAST
   for (x = 0; x < 16; x += sizeof(LTC_FAST_TYPE)) {
      *((LTC_FAST_TYPE*)&P[x]) = *((LTC_FAST_TYPE*)&C[x]) ^ *((LTC_FAST_TYPE*)&T[x]);
   }
#else
   for (x = 0; x < 16; x++) {
       P[x] = C[x] ^ T[x];
   }
#endif
     
   err = cipher_descriptor[xts->cipher]->ecb_decrypt(P, P, &xts->key1);  

#ifdef LTC_FAST
   for (x = 0; x < 16; x += sizeof(LTC_FAST_TYPE)) {
      *((LTC_FAST_TYPE*)&P[x]) ^=  *((LTC_FAST_TYPE*)&T[x]);
   }
#else
   for (x = 0; x < 16; x++) {
       P[x] = P[x] ^ T[x];
   }
#endif

   /* LFSR the tweak */
   xts_mult_x(T);

   return err;
}   

/** XTS Decryption
  @param ct     [in] Ciphertext
  @param ptlen  Length of plaintext (and ciphertext)
  @param pt     [out]  Plaintext
  @param tweak  [in] The 128--bit encryption tweak (e.g. sector number)
  @param xts    The XTS structure
  Returns CRYPT_OK upon success
*/
int xts_decrypt(const unsigned char *ct, unsigned long ptlen, unsigned char *pt, unsigned char *tweak,
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

   if (desc->accel_xts_decrypt && lim > 0) {

	   /* use accelerated decryption for whole blocks */
	   if ((err = desc->accel_xts_decrypt(ct, pt, lim, tweak, &xts->key1,
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
         if ((err = tweak_uncrypt(ct, pt, T, xts)) != CRYPT_OK) {
            return err;
         }
         ct += 16;
         pt += 16;
      }
   }

   /* if ptlen not divide 16 then */
   if (mo > 0) {
      XMEMCPY(CC, T, 16);
      xts_mult_x(CC);

      /* PP = tweak decrypt block m-1 */
      if ((err = tweak_uncrypt(ct, PP, CC, xts)) != CRYPT_OK) {
         return err;
      }

      /* Pm = first ptlen % 16 bytes of PP */
      for (i = 0; i < mo; i++) {
          CC[i]    = ct[16+i];
          pt[16+i] = PP[i];
      }
      for (; i < 16; i++) {
          CC[i] = PP[i];
      }

      /* Pm-1 = Tweak uncrypt CC */
      if ((err = tweak_uncrypt(CC, pt, T, xts)) != CRYPT_OK) {
         return err;
      }
   }
   /* Decrypt the tweak back */
   if ((err = desc->ecb_decrypt(T, tweak, &xts->key2)) != CRYPT_OK) {
      return err;
   }

   return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/modes/xts/xts_decrypt.c,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2007/05/12 14:05:56 $ */
