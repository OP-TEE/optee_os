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

/**
   @file eax_done.c
   EAX implementation, terminate session, by Tom St Denis
*/
#include "tomcrypt.h"

#ifdef LTC_EAX_MODE

/**
   Terminate an EAX session and get the tag.
   @param eax       The EAX state
   @param tag       [out] The destination of the authentication tag
   @param taglen    [in/out] The max length and resulting length of the authentication tag
   @return CRYPT_OK if successful
*/
int eax_done(eax_state *eax, unsigned char *tag, unsigned long *taglen)
{
   int           err;
   unsigned char *headermac, *ctmac;
   unsigned long x, len;

   LTC_ARGCHK(eax    != NULL);
   LTC_ARGCHK(tag    != NULL);
   LTC_ARGCHK(taglen != NULL);

   /* allocate ram */
   headermac = XMALLOC(MAXBLOCKSIZE);
   ctmac     = XMALLOC(MAXBLOCKSIZE);

   if (headermac == NULL || ctmac == NULL) {
      if (headermac != NULL) {
         XFREE(headermac);
      }
      if (ctmac != NULL) {
         XFREE(ctmac);
      }
      return CRYPT_MEM;
   }

   /* finish ctomac */
   len = MAXBLOCKSIZE;
   if ((err = omac_done(&eax->ctomac, ctmac, &len)) != CRYPT_OK) {
      goto LBL_ERR; 
   }

   /* finish headeromac */

   /* note we specifically don't reset len so the two lens are minimal */

   if ((err = omac_done(&eax->headeromac, headermac, &len)) != CRYPT_OK) {
      goto LBL_ERR; 
   }

   /* terminate the CTR chain */
   if ((err = ctr_done(&eax->ctr)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* compute N xor H xor C */
   for (x = 0; x < len && x < *taglen; x++) {
       tag[x] = eax->N[x] ^ headermac[x] ^ ctmac[x];
   }
   *taglen = x;

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(ctmac,     MAXBLOCKSIZE);
   zeromem(headermac, MAXBLOCKSIZE);
   zeromem(eax,       sizeof(*eax));
#endif

   XFREE(ctmac);
   XFREE(headermac);

   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/encauth/eax/eax_done.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2007/05/12 14:32:35 $ */
