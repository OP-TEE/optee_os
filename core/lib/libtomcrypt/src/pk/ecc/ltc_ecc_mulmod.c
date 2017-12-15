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

/* Implements ECC over Z/pZ for curve y^2 = x^3 - 3x + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */
#include "tomcrypt.h"

/**
  @file ltc_ecc_mulmod.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC
#ifndef LTC_ECC_TIMING_RESISTANT

/* size of sliding window, don't change this! MUST BE A POWER OF TWO */
#define WINSIZE 4
#define WINVARS (1 << (WINSIZE - 1))

/**
   Perform a point multiplication
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return CRYPT_OK on success
*/
int ltc_ecc_mulmod(void *k, ecc_point *G, ecc_point *R, void *modulus, int map)
{
   ecc_point *tG, *M[WINVARS];
   int        i, j, err;
   void       *mu, *mp;
   ltc_mp_digit buf;
   int        first, bitbuf, bitcpy, bitcnt, mode, digidx;

   LTC_ARGCHK(k       != NULL);
   LTC_ARGCHK(G       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != CRYPT_OK) {
      return err;
   }
   if ((err = mp_init(&mu)) != CRYPT_OK) {
      mp_montgomery_free(mp);
      return err;
   }
   if ((err = mp_montgomery_normalization(mu, modulus)) != CRYPT_OK) {
      mp_montgomery_free(mp);
      mp_clear(mu);
      return err;
   }

  /* alloc ram for window temps */
  for (i = 0; i < WINVARS; i++) {
      M[i] = ltc_ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ltc_ecc_del_point(M[j]);
         }
         mp_montgomery_free(mp);
         mp_clear(mu);
         return CRYPT_MEM;
      }
  }

   /* make a copy of G incase R==G */
   tG = ltc_ecc_new_point();
   if (tG == NULL)                                                                   { err = CRYPT_MEM; goto done; }

   /* tG = G  and convert to montgomery */
   if (mp_cmp_d(mu, 1) == LTC_MP_EQ) {
      if ((err = mp_copy(G->x, tG->x)) != CRYPT_OK)                                  { goto done; }
      if ((err = mp_copy(G->y, tG->y)) != CRYPT_OK)                                  { goto done; }
      if ((err = mp_copy(G->z, tG->z)) != CRYPT_OK)                                  { goto done; }
   } else {
      if ((err = mp_mulmod(G->x, mu, modulus, tG->x)) != CRYPT_OK)                   { goto done; }
      if ((err = mp_mulmod(G->y, mu, modulus, tG->y)) != CRYPT_OK)                   { goto done; }
      if ((err = mp_mulmod(G->z, mu, modulus, tG->z)) != CRYPT_OK)                   { goto done; }
   }
   mp_clear(mu);
   mu = NULL;

   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == [WINVARS].G */
   if ((err = ltc_mp.ecc_ptdbl(tG, M[0], modulus, mp)) != CRYPT_OK)                 { goto done; }
   for (j = 1; j < (WINSIZE-1); ++j) {
       if ((err = ltc_mp.ecc_ptdbl(M[0], M[0], modulus, mp)) != CRYPT_OK)               { goto done; }
   }

   /* now find (WINVARS+k)G for k=1..(WINVARS-1) */
   for (j = (WINVARS + 1); j < (2*WINVARS); j++) {
       if ((err = ltc_mp.ecc_ptadd(M[j-(WINVARS + 1)], tG, M[j-WINVARS], modulus, mp)) != CRYPT_OK)   { goto done; }
   }

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = mp_get_digit_count(k) - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
     if (--bitcnt == 0) {
       if (digidx == -1) {
          break;
       }
       buf    = mp_get_digit(k, digidx);
       bitcnt = (int) ltc_mp.bits_per_digit;
       --digidx;
     }

     /* grab the next msb from the ltiplicand */
     i = (buf >> (ltc_mp.bits_per_digit - 1)) & 1;
     buf <<= 1;

     /* skip leading zero bits */
     if (mode == 0 && i == 0) {
        continue;
     }

     /* if the bit is zero and mode == 1 then we double */
     if (mode == 1 && i == 0) {
        if ((err = ltc_mp.ecc_ptdbl(R, R, modulus, mp)) != CRYPT_OK)                 { goto done; }
        continue;
     }

     /* else we add it to the window */
     bitbuf |= (i << (WINSIZE - ++bitcpy));
     mode = 2;

     if (bitcpy == WINSIZE) {
       /* if this is the first window we do a simple copy */
       if (first == 1) {
          /* R = kG [k = first window] */
          if ((err = mp_copy(M[bitbuf-WINVARS]->x, R->x)) != CRYPT_OK)                     { goto done; }
          if ((err = mp_copy(M[bitbuf-WINVARS]->y, R->y)) != CRYPT_OK)                     { goto done; }
          if ((err = mp_copy(M[bitbuf-WINVARS]->z, R->z)) != CRYPT_OK)                     { goto done; }
          first = 0;
       } else {
         /* normal window */
         /* ok window is filled so double as required and add  */
         /* double first */
         for (j = 0; j < WINSIZE; j++) {
           if ((err = ltc_mp.ecc_ptdbl(R, R, modulus, mp)) != CRYPT_OK)              { goto done; }
         }

         /* then add, bitbuf will be WINVARS..(2*WINVARS - 1) guaranteed */
         if ((err = ltc_mp.ecc_ptadd(R, M[bitbuf-WINVARS], R, modulus, mp)) != CRYPT_OK)   { goto done; }
       }
       /* empty window and reset */
       bitcpy = bitbuf = 0;
       mode = 1;
    }
  }

   /* if bits remain then double/add */
   if (mode == 2 && bitcpy > 0) {
     /* double then add */
     for (j = 0; j < bitcpy; j++) {
       /* only double if we have had at least one add first */
       if (first == 0) {
          if ((err = ltc_mp.ecc_ptdbl(R, R, modulus, mp)) != CRYPT_OK)              { goto done; }
       }

       bitbuf <<= 1;
       if ((bitbuf & (1 << WINSIZE)) != 0) {
         if (first == 1){
            /* first add, so copy */
            if ((err = mp_copy(tG->x, R->x)) != CRYPT_OK)                           { goto done; }
            if ((err = mp_copy(tG->y, R->y)) != CRYPT_OK)                           { goto done; }
            if ((err = mp_copy(tG->z, R->z)) != CRYPT_OK)                           { goto done; }
            first = 0;
         } else {
            /* then add */
            if ((err = ltc_mp.ecc_ptadd(R, tG, R, modulus, mp)) != CRYPT_OK)        { goto done; }
         }
       }
     }
   }

   /* map R back from projective space */
   if (map) {
      err = ltc_ecc_map(R, modulus, mp);
   } else {
      err = CRYPT_OK;
   }
done:
   if (mu != NULL) {
      mp_clear(mu);
   }
   mp_montgomery_free(mp);
   ltc_ecc_del_point(tG);
   for (i = 0; i < WINVARS; i++) {
       ltc_ecc_del_point(M[i]);
   }
   return err;
}

#endif

#undef WINSIZE

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ltc_ecc_mulmod.c,v $ */
/* $Revision: 1.26 $ */
/* $Date: 2007/05/12 14:32:35 $ */
