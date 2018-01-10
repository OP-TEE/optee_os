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
 *
 * Added RSA blinding --nmav
 */
#include "tomcrypt.h"

/**
  @file rsa_exptmod.c
  RSA PKCS exptmod, Tom St Denis
*/

#ifdef LTC_MRSA

/** 
   Compute an RSA modular exponentiation 
   @param in         The input data to send into RSA
   @param inlen      The length of the input (octets)
   @param out        [out] The destination 
   @param outlen     [in/out] The max size and resulting size of the output
   @param which      Which exponent to use, e.g. PK_PRIVATE or PK_PUBLIC
   @param key        The RSA key to use 
   @return CRYPT_OK if successful
*/   
int rsa_exptmod(const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen, int which,
                      rsa_key *key)
{
   void         *tmp, *tmpa, *tmpb;
#ifdef LTC_RSA_BLINDING
   void        *rnd, *rndi /* inverse of rnd */;
#endif
   unsigned long x;
   int           err, no_crt;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
  
   /* is the key of the right type for the operation? */
   if (which == PK_PRIVATE && (key->type != PK_PRIVATE)) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* must be a private or public operation */
   if (which != PK_PRIVATE && which != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* init and copy into tmp */
   if ((err = mp_init_multi(&tmp, &tmpa, &tmpb,
#ifdef LTC_RSA_BLINDING
                                               &rnd, &rndi,
#endif /* LTC_RSA_BLINDING */
                                                           NULL)) != CRYPT_OK)
        { return err; }
   if ((err = mp_read_unsigned_bin(tmp, (unsigned char *)in, (int)inlen)) != CRYPT_OK)
        { goto error; }

   /* sanity check on the input */
   if (mp_cmp(key->N, tmp) == LTC_MP_LT) {
      err = CRYPT_PK_INVALID_SIZE;
      goto error;
   }

   if (which == PK_PRIVATE) {
#ifdef LTC_RSA_BLINDING
      /* do blinding */
      err = mp_rand(rnd, mp_get_digit_count(key->N));
      if (err != CRYPT_OK) {
             goto error;
      }

      /* rndi = 1/rnd mod N */
      err = mp_invmod(rnd, key->N, rndi);
      if (err != CRYPT_OK) {
             goto error;
      }

      /* rnd = rnd^e */
      err = mp_exptmod( rnd, key->e, key->N, rnd);
      if (err != CRYPT_OK) {
             goto error;
      }

      /* tmp = tmp*rnd mod N */
      err = mp_mulmod( tmp, rnd, key->N, tmp);
      if (err != CRYPT_OK) {
             goto error;
      }
#endif /* LTC_RSA_BLINDING */

      no_crt = (key->dP == NULL) || (mp_get_digit_count(key->dP) == 0);

      if (no_crt) {
         /*
          * In case CRT optimization parameters are not provided,
          * the private key is directly used to exptmod it
          */
         if ((err = mp_exptmod(tmp, key->d, key->N, tmp)) != CRYPT_OK)                              { goto error; }
      } else {
         /* tmpa = tmp^dP mod p */
         if ((err = mp_exptmod(tmp, key->dP, key->p, tmpa)) != CRYPT_OK)                            { goto error; }

         /* tmpb = tmp^dQ mod q */
         if ((err = mp_exptmod(tmp, key->dQ, key->q, tmpb)) != CRYPT_OK)                            { goto error; }

         /* tmp = (tmpa - tmpb) * qInv (mod p) */
         if ((err = mp_sub(tmpa, tmpb, tmp)) != CRYPT_OK)                                           { goto error; }
         if ((err = mp_mulmod(tmp, key->qP, key->p, tmp)) != CRYPT_OK)                              { goto error; }

         /* tmp = tmpb + q * tmp */
         if ((err = mp_mul(tmp, key->q, tmp)) != CRYPT_OK)                                          { goto error; }
         if ((err = mp_add(tmp, tmpb, tmp)) != CRYPT_OK)                                            { goto error; }
      }

      #ifdef LTC_RSA_BLINDING
      /* unblind */
      err = mp_mulmod( tmp, rndi, key->N, tmp);
      if (err != CRYPT_OK) {
             goto error;
      }
      #endif

      #ifdef LTC_RSA_CRT_HARDENING
      if (!no_crt) {
         if ((err = mp_exptmod(tmp, key->e, key->N, tmpa)) != CRYPT_OK)                              { goto error; }
         if ((err = mp_read_unsigned_bin(tmpb, (unsigned char *)in, (int)inlen)) != CRYPT_OK)        { goto error; }
         if (mp_cmp(tmpa, tmpb) != LTC_MP_EQ)                                     { err = CRYPT_ERROR; goto error; }
      }
      #endif
   } else {
      /* exptmod it */
      if ((err = mp_exptmod(tmp, key->e, key->N, tmp)) != CRYPT_OK)                                { goto error; }
   }

   /* read it back */
   x = (unsigned long)mp_unsigned_bin_size(key->N);
   if (x > *outlen) {
      *outlen = x;
      err = CRYPT_BUFFER_OVERFLOW;
      goto error;
   }

   /* this should never happen ... */
   if (mp_unsigned_bin_size(tmp) > mp_unsigned_bin_size(key->N)) {
      err = CRYPT_ERROR;
      goto error;
   }
   *outlen = x;

   /* convert it */
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin(tmp, out+(x-mp_unsigned_bin_size(tmp)))) != CRYPT_OK)               { goto error; }

   /* clean up and return */
   err = CRYPT_OK;
error:
   mp_clear_multi(
#ifdef LTC_RSA_BLINDING
                  rndi, rnd,
#endif /* LTC_RSA_BLINDING */
                             tmpb, tmpa, tmp, NULL);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/rsa/rsa_exptmod.c,v $ */
/* $Revision: 1.18 $ */
/* $Date: 2007/05/12 14:32:35 $ */
