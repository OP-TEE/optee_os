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
  @file xcbc_process.c
  XCBC Support, process blocks with XCBC
*/

#ifdef LTC_XCBC

/** Process data through XCBC-MAC
  @param xcbc     The XCBC-MAC state
  @param in       Input data to process
  @param inlen    Length of input in octets
  Return CRYPT_OK on success
*/
int xcbc_process(xcbc_state *xcbc, const unsigned char *in, unsigned long inlen)
{
   int err;
#ifdef LTC_FAST
   int x;
#endif

   LTC_ARGCHK(xcbc != NULL);
   LTC_ARGCHK(in   != NULL);

   /* check structure */
   if ((err = cipher_is_valid(xcbc->cipher)) != CRYPT_OK) {
      return err;
   }

   if ((xcbc->blocksize > cipher_descriptor[xcbc->cipher].block_length) || (xcbc->blocksize < 0) ||
       (xcbc->buflen > xcbc->blocksize) || (xcbc->buflen < 0)) {
      return CRYPT_INVALID_ARG;
   }

#ifdef LTC_FAST
   if (xcbc->buflen == 0) {
       while (inlen > (unsigned long)xcbc->blocksize) {
           for (x = 0; x < xcbc->blocksize; x += sizeof(LTC_FAST_TYPE)) {
              *((LTC_FAST_TYPE*)&(xcbc->IV[x])) ^= *((LTC_FAST_TYPE*)&(in[x]));
           }
           cipher_descriptor[xcbc->cipher].ecb_encrypt(xcbc->IV, xcbc->IV, &xcbc->key);
           in    += xcbc->blocksize;
           inlen -= xcbc->blocksize;
       }
  }
#endif

   while (inlen) {
     if (xcbc->buflen == xcbc->blocksize) {
         cipher_descriptor[xcbc->cipher].ecb_encrypt(xcbc->IV, xcbc->IV, &xcbc->key);
         xcbc->buflen = 0;
     }
     xcbc->IV[xcbc->buflen++] ^= *in++;
     --inlen;
  }
  return CRYPT_OK;       
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/mac/xcbc/xcbc_process.c,v $ */
/* $Revision: 1.10 $ */
/* $Date: 2006/12/28 01:27:23 $ */

