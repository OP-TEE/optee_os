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
  Process plaintext/ciphertext through CCM
  @param ccm       The CCM state
  @param pt        The plaintext
  @param ptlen     The plaintext length (ciphertext length is the same)
  @param ct        The ciphertext
  @param direction Encrypt or Decrypt mode (CCM_ENCRYPT or CCM_DECRYPT)
  @return CRYPT_OK on success
 */
int ccm_process(ccm_state *ccm,
                unsigned char *pt,     unsigned long ptlen,
                unsigned char *ct,
                int direction)
{
   unsigned char z, b;
   unsigned long y;
   int err;

   LTC_ARGCHK(ccm != NULL);

   /* Check aad has been correctly added */
   if (ccm->aadlen != ccm->current_aadlen) {
      return CRYPT_ERROR;
   }

   /* Check we do not process too much data */
   if (ccm->ptlen < ccm->current_ptlen + ptlen) {
      return CRYPT_ERROR;
   }
   ccm->current_ptlen += ptlen;

   /* now handle the PT */
   if (ptlen > 0) {
      LTC_ARGCHK(pt != NULL);
      LTC_ARGCHK(ct != NULL);

      for (y = 0; y < ptlen; y++) {
         /* increment the ctr? */
         if (ccm->CTRlen == 16) {
            for (z = 15; z > 15-ccm->L; z--) {
               ccm->ctr[z] = (ccm->ctr[z] + 1) & 255;
               if (ccm->ctr[z]) break;
            }
            if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->ctr, ccm->CTRPAD, &ccm->K)) != CRYPT_OK) {
               return err;
            }
            ccm->CTRlen = 0;
         }

         /* if we encrypt we add the bytes to the MAC first */
         if (direction == CCM_ENCRYPT) {
            b     = pt[y];
            ct[y] = b ^ ccm->CTRPAD[ccm->CTRlen++];
         } else {
            b     = ct[y] ^ ccm->CTRPAD[ccm->CTRlen++];
            pt[y] = b;
         }

         if (ccm->x == 16) {
            if ((err = cipher_descriptor[ccm->cipher]->ecb_encrypt(ccm->PAD, ccm->PAD, &ccm->K)) != CRYPT_OK) {
               return err;
            }
            ccm->x = 0;
         }
         ccm->PAD[ccm->x++] ^= b;
      }
   }

   return CRYPT_OK;
}

#endif
