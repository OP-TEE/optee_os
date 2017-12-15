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
  Add AAD to the CCM state
  @param ccm       The CCM state
  @param adata     The additional authentication data to add to the CCM state
  @param adatalen  The length of the AAD data.
  @return CRYPT_OK on success
 */
int ccm_add_aad(ccm_state *ccm,
                const unsigned char *adata,  unsigned long adatalen)
{
   unsigned long y;
   int            err;

   LTC_ARGCHK(ccm   != NULL);
   LTC_ARGCHK(adata != NULL);

   if (ccm->aadlen < ccm->current_aadlen + adatalen) {
      return CRYPT_INVALID_ARG;
   }
   ccm->current_aadlen += adatalen;

   /* now add the data */
   for (y = 0; y < adatalen; y++) {
      if (ccm->x == 16) {
         /* full block so let's encrypt it */
         if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->PAD, ccm->PAD, &ccm->K)) != CRYPT_OK) {
            return CRYPT_ERROR;
         }
         ccm->x = 0;
      }
      ccm->PAD[ccm->x++] ^= adata[y];
   }

   /* remainder? */
   if (ccm->aadlen == ccm->current_aadlen) {
      if (ccm->x != 0) {
         if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->PAD, ccm->PAD, &ccm->K)) != CRYPT_OK) {
            return CRYPT_ERROR;
         }
      }
      ccm->x = 0;
   }

   return CRYPT_OK;
}

#endif
