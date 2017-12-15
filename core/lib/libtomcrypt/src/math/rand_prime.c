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

#if !defined LTC_NO_MATH && !defined LTC_NO_PRNGS

/**
  @file rand_prime.c
  Generate a random prime, Tom St Denis
*/  

#define USE_BBS 1

int rand_prime(void *N, long len, prng_state *prng, int wprng)
{
   int            err, res, type;
   unsigned char *buf;

   LTC_ARGCHK(N != NULL);

   /* get type */
   if (len < 0) {
      type = USE_BBS;
      len = -len;
   } else {
      type = 0;
   }

   /* allow sizes between 2 and 512 bytes for a prime size */
   if (len < 2 || len > 512) { 
      return CRYPT_INVALID_PRIME_SIZE;
   }
   
   /* valid PRNG? Better be! */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err; 
   }

   /* allocate buffer to work with */
   buf = XCALLOC(1, len);
   if (buf == NULL) {
       return CRYPT_MEM;
   }

   do {
      /* generate value */
      if (prng_descriptor[wprng]->read(buf, len, prng) != (unsigned long)len) {
         XFREE(buf);
         return CRYPT_ERROR_READPRNG;
      }

      /* munge bits */
      buf[0]     |= 0x80 | 0x40;
      buf[len-1] |= 0x01 | ((type & USE_BBS) ? 0x02 : 0x00);
 
      /* load value */
      if ((err = mp_read_unsigned_bin(N, buf, len)) != CRYPT_OK) {
         XFREE(buf);
         return err;
      }

      /* test */
      if ((err = mp_prime_is_prime(N, 8, &res)) != CRYPT_OK) {
         XFREE(buf);
         return err;
      }
   } while (res == LTC_MP_NO);

#ifdef LTC_CLEAN_STACK
   zeromem(buf, len);
#endif

   XFREE(buf);
   return CRYPT_OK;
}
      
#endif /* LTC_NO_MATH */


/* $Source: /cvs/libtom/libtomcrypt/src/math/rand_prime.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2006/12/28 01:27:23 $ */
