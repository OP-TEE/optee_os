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
  @file xcbc_done.c
  XCBC Support, terminate the state
*/

#ifdef LTC_XCBC

/** Terminate the XCBC-MAC state
  @param xcbc     XCBC state to terminate
  @param out      [out] Destination for the MAC tag
  @param outlen   [in/out] Destination size and final tag size
  Return CRYPT_OK on success
*/
int xcbc_done(xcbc_state *xcbc, unsigned char *out, unsigned long *outlen)
{
   int err, x;
   LTC_ARGCHK(xcbc != NULL);
   LTC_ARGCHK(out  != NULL);

   /* check structure */
   if ((err = cipher_is_valid(xcbc->cipher)) != CRYPT_OK) {
      return err;
   }

   if ((xcbc->blocksize > cipher_descriptor[xcbc->cipher].block_length) || (xcbc->blocksize < 0) ||
       (xcbc->buflen > xcbc->blocksize) || (xcbc->buflen < 0)) {
      return CRYPT_INVALID_ARG;
   }

   /* which key do we use? */
   if (xcbc->buflen == xcbc->blocksize) {
      /* k2 */
      for (x = 0; x < xcbc->blocksize; x++) {
         xcbc->IV[x] ^= xcbc->K[1][x];
      }
   } else {
      xcbc->IV[xcbc->buflen] ^= 0x80;
      /* k3 */
      for (x = 0; x < xcbc->blocksize; x++) {
         xcbc->IV[x] ^= xcbc->K[2][x];
      }
   }

   /* encrypt */
   cipher_descriptor[xcbc->cipher].ecb_encrypt(xcbc->IV, xcbc->IV, &xcbc->key);
   cipher_descriptor[xcbc->cipher].done(&xcbc->key);

   /* extract tag */
   for (x = 0; x < xcbc->blocksize && (unsigned long)x < *outlen; x++) {
      out[x] = xcbc->IV[x];
   }
   *outlen = x;
  
#ifdef LTC_CLEAN_STACK
   zeromem(xcbc, sizeof(*xcbc));
#endif
   return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/mac/xcbc/xcbc_done.c,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2006/12/28 01:27:23 $ */

