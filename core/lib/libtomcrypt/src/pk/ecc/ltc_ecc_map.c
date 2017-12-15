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
  @file ltc_ecc_map.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/**
  Map a projective jacbobian point back to affine space
  @param P        [in/out] The point to map
  @param modulus  The modulus of the field the ECC curve is in
  @param mp       The "b" value from montgomery_setup()
  @return CRYPT_OK on success
*/
int ltc_ecc_map(ecc_point *P, void *modulus, void *mp)
{
   void *t1, *t2;
   int   err;

   LTC_ARGCHK(P       != NULL);
   LTC_ARGCHK(modulus != NULL);
   LTC_ARGCHK(mp      != NULL);

   if ((err = mp_init_multi(&t1, &t2, NULL)) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* first map z back to normal */
   if ((err = mp_montgomery_reduce(P->z, modulus, mp)) != CRYPT_OK)           { goto done; }

   /* get 1/z */
   if ((err = mp_invmod(P->z, modulus, t1)) != CRYPT_OK)                      { goto done; }
 
   /* get 1/z^2 and 1/z^3 */
   if ((err = mp_sqr(t1, t2)) != CRYPT_OK)                                    { goto done; }
   if ((err = mp_mod(t2, modulus, t2)) != CRYPT_OK)                           { goto done; }
   if ((err = mp_mul(t1, t2, t1)) != CRYPT_OK)                                { goto done; }
   if ((err = mp_mod(t1, modulus, t1)) != CRYPT_OK)                           { goto done; }

   /* multiply against x/y */
   if ((err = mp_mul(P->x, t2, P->x)) != CRYPT_OK)                            { goto done; }
   if ((err = mp_montgomery_reduce(P->x, modulus, mp)) != CRYPT_OK)           { goto done; }
   if ((err = mp_mul(P->y, t1, P->y)) != CRYPT_OK)                            { goto done; }
   if ((err = mp_montgomery_reduce(P->y, modulus, mp)) != CRYPT_OK)           { goto done; }
   if ((err = mp_set(P->z, 1)) != CRYPT_OK)                                   { goto done; }

   err = CRYPT_OK;
done:
   mp_clear_multi(t1, t2, NULL);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ltc_ecc_map.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2007/05/12 14:32:35 $ */
