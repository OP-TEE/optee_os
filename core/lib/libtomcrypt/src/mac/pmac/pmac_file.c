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
   @file pmac_file.c
   PMAC implementation, process a file, by Tom St Denis 
*/

#ifdef LTC_PMAC

/**
   PMAC a file 
   @param cipher       The index of the cipher desired
   @param key          The secret key
   @param keylen       The length of the secret key (octets)
   @param filename     The name of the file to send through PMAC
   @param out          [out] Destination for the authentication tag
   @param outlen       [in/out] Max size and resulting size of the authentication tag
   @return CRYPT_OK if successful, CRYPT_NOP if file support has been disabled
*/
int pmac_file(int cipher, 
              const unsigned char *key, unsigned long keylen,
              const char *filename, 
                    unsigned char *out, unsigned long *outlen)
{
#ifdef LTC_NO_FILE
   return CRYPT_NOP;
#else
   int err, x;
   pmac_state pmac;
   FILE *in;
   unsigned char buf[512];


   LTC_ARGCHK(key      != NULL);
   LTC_ARGCHK(filename != NULL);
   LTC_ARGCHK(out      != NULL);
   LTC_ARGCHK(outlen   != NULL);

   in = fopen(filename, "rb");
   if (in == NULL) {
      return CRYPT_FILE_NOTFOUND;
   }

   if ((err = pmac_init(&pmac, cipher, key, keylen)) != CRYPT_OK) {
      fclose(in);
      return err;
   }

   do {
      x = fread(buf, 1, sizeof(buf), in);
      if ((err = pmac_process(&pmac, buf, x)) != CRYPT_OK) {
         fclose(in);
         return err;
      }
   } while (x == sizeof(buf));
   fclose(in);

   if ((err = pmac_done(&pmac, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
#endif
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/mac/pmac/pmac_file.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2006/12/28 01:27:23 $ */
