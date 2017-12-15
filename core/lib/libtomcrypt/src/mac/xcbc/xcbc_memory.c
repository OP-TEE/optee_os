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
  XCBC Support, XCBC-MAC a block of memory
*/

#ifdef LTC_XCBC

/** XCBC-MAC a block of memory 
  @param cipher     Index of cipher to use
  @param key        [in]  Secret key
  @param keylen     Length of key in octets
  @param in         [in]  Message to MAC
  @param inlen      Length of input in octets
  @param out        [out] Destination for the MAC tag
  @param outlen     [in/out] Output size and final tag size
  Return CRYPT_OK on success.
*/
int xcbc_memory(int cipher, 
               const unsigned char *key, unsigned long keylen,
               const unsigned char *in,  unsigned long inlen,
                     unsigned char *out, unsigned long *outlen)
{
   xcbc_state *xcbc;
   int         err;

   /* is the cipher valid? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* Use accelerator if found */
   if (cipher_descriptor[cipher].xcbc_memory != NULL) {
      return cipher_descriptor[cipher].xcbc_memory(key, keylen, in, inlen, out, outlen);
   }

   xcbc = XCALLOC(1, sizeof(*xcbc));
   if (xcbc == NULL) {
      return CRYPT_MEM;
   }

   if ((err = xcbc_init(xcbc, cipher, key, keylen)) != CRYPT_OK) {
     goto done;
   }

   if ((err = xcbc_process(xcbc, in, inlen)) != CRYPT_OK) {
     goto done;
   }

   err = xcbc_done(xcbc, out, outlen);
done:
   XFREE(xcbc);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/mac/xcbc/xcbc_memory.c,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2006/12/28 01:27:23 $ */
