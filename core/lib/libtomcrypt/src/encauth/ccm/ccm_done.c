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
  Terminate a CCM stream
  @param ccm     The CCM state
  @param tag     [out] The destination for the MAC tag
  @param taglen  [in/out]  The length of the MAC tag
  @return CRYPT_OK on success
 */
int ccm_done(ccm_state *ccm,
             unsigned char *tag,    unsigned long *taglen)
{
   unsigned long x, y;
   int            err;

   LTC_ARGCHK(ccm != NULL);

   /* Check all data have been processed */
   if (ccm->ptlen != ccm->current_ptlen) {
      return CRYPT_ERROR;
   }

   LTC_ARGCHK(tag    != NULL);
   LTC_ARGCHK(taglen != NULL);

   if (ccm->x != 0) {
      if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->PAD, ccm->PAD, &ccm->K)) != CRYPT_OK) {
         return err;
      }
   }

   /* setup CTR for the TAG (zero the count) */
   for (y = 15; y > 15 - ccm->L; y--) {
      ccm->ctr[y] = 0x00;
   }
   if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->ctr, ccm->CTRPAD, &ccm->K)) != CRYPT_OK) {
      return err;
   }

   cipher_descriptor[ccm->cipher]->done(&ccm->K);

   /* store the TAG */
   for (x = 0; x < 16 && x < *taglen; x++) {
      tag[x] = ccm->PAD[x] ^ ccm->CTRPAD[x];
   }
   *taglen = x;

   return CRYPT_OK;
}

#endif
