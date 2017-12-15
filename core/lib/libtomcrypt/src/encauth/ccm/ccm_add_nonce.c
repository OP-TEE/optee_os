// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2001-2007, Tom St Denis
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifdef LTC_CCM_MODE

/**
  Add nonce data to the CCM state
  @param ccm       The CCM state
  @param nonce     The nonce data to add
  @param noncelen  The length of the nonce
  @return CRYPT_OK on success
 */
int ccm_add_nonce(ccm_state *ccm,
                  const unsigned char *nonce,     unsigned long noncelen)
{
   unsigned long x, y, len;
   int           err;

   LTC_ARGCHK(ccm   != NULL);
   LTC_ARGCHK(nonce != NULL);

   /* increase L to match the nonce len */
   ccm->noncelen = (noncelen > 13) ? 13 : noncelen;
   if ((15 - ccm->noncelen) > ccm->L) {
      ccm->L = 15 - ccm->noncelen;
   }

   /* decrease noncelen to match L */
   if ((ccm->noncelen + ccm->L) > 15) {
      ccm->noncelen = 15 - ccm->L;
   }

   /* form B_0 == flags | Nonce N | l(m) */
   x = 0;
   ccm->PAD[x++] = (unsigned char)(((ccm->aadlen > 0) ? (1<<6) : 0) |
		   (((ccm->taglen - 2)>>1)<<3)        |
		   (ccm->L-1));

   /* nonce */
   for (y = 0; y < (16 - (ccm->L + 1)); y++) {
      ccm->PAD[x++] = nonce[y];
   }

   /* store len */
   len = ccm->ptlen;

   /* shift len so the upper bytes of len are the contents of the length */
   for (y = ccm->L; y < 4; y++) {
      len <<= 8;
   }

   /* store l(m) (only store 32-bits) */
   for (y = 0; ccm->L > 4 && (ccm->L-y)>4; y++) {
      ccm->PAD[x++] = 0;
   }
   for (; y < ccm->L; y++) {
      ccm->PAD[x++] = (unsigned char)((len >> 24) & 255);
      len <<= 8;
   }

   /* encrypt PAD */
   if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->PAD, ccm->PAD, &ccm->K)) != CRYPT_OK) {
      return err;
   }

   /* handle header */
   ccm->x = 0;
   if (ccm->aadlen > 0) {
      /* store length */
      if (ccm->aadlen < ((1UL<<16) - (1UL<<8))) {
         ccm->PAD[ccm->x++] ^= (ccm->aadlen>>8) & 255;
         ccm->PAD[ccm->x++] ^= ccm->aadlen & 255;
      } else {
         ccm->PAD[ccm->x++] ^= 0xFF;
         ccm->PAD[ccm->x++] ^= 0xFE;
         ccm->PAD[ccm->x++] ^= (ccm->aadlen>>24) & 255;
         ccm->PAD[ccm->x++] ^= (ccm->aadlen>>16) & 255;
         ccm->PAD[ccm->x++] ^= (ccm->aadlen>>8) & 255;
         ccm->PAD[ccm->x++] ^= ccm->aadlen & 255;
      }
   }

   /* setup the ctr counter */
   x = 0;

   /* flags */
   ccm->ctr[x++] = (unsigned char)ccm->L-1;

   /* nonce */
   for (y = 0; y < (16 - (ccm->L+1)); ++y) {
      ccm->ctr[x++] = nonce[y];
   }
   /* offset */
   while (x < 16) {
      ccm->ctr[x++] = 0;
   }

   ccm->CTRlen = 16;
   return CRYPT_OK;
}

#endif
