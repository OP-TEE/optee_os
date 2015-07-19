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
  @file ecc_test.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Perform on the ECC system
  @return CRYPT_OK if successful
*/
int ecc_test(void)
{
   void     *modulus, *order;
   ecc_point  *G, *GG;
   int i, err, primality;

   if ((err = mp_init_multi(&modulus, &order, NULL)) != CRYPT_OK) {
      return err;
   }

   G   = ltc_ecc_new_point();
   GG  = ltc_ecc_new_point();
   if (G == NULL || GG == NULL) {
      mp_clear_multi(modulus, order, NULL);
      ltc_ecc_del_point(G);
      ltc_ecc_del_point(GG);
      return CRYPT_MEM;
   }

   for (i = 0; ltc_ecc_sets[i].size; i++) {
       #if 0
          printf("Testing %d\n", ltc_ecc_sets[i].size);
       #endif
       if ((err = mp_read_radix(modulus, (char *)ltc_ecc_sets[i].prime, 16)) != CRYPT_OK)   { goto done; }
       if ((err = mp_read_radix(order, (char *)ltc_ecc_sets[i].order, 16)) != CRYPT_OK)     { goto done; }

       /* is prime actually prime? */
       if ((err = mp_prime_is_prime(modulus, 8, &primality)) != CRYPT_OK)                   { goto done; }
       if (primality == 0) {
          err = CRYPT_FAIL_TESTVECTOR;
          goto done;
       }

       /* is order prime ? */
       if ((err = mp_prime_is_prime(order, 8, &primality)) != CRYPT_OK)                     { goto done; }
       if (primality == 0) {
          err = CRYPT_FAIL_TESTVECTOR;
          goto done;
       }

       if ((err = mp_read_radix(G->x, (char *)ltc_ecc_sets[i].Gx, 16)) != CRYPT_OK)         { goto done; }
       if ((err = mp_read_radix(G->y, (char *)ltc_ecc_sets[i].Gy, 16)) != CRYPT_OK)         { goto done; }
       mp_set(G->z, 1);

       /* then we should have G == (order + 1)G */
       if ((err = mp_add_d(order, 1, order)) != CRYPT_OK)                                   { goto done; }
       if ((err = ltc_mp.ecc_ptmul(order, G, GG, modulus, 1)) != CRYPT_OK)                  { goto done; }
       if (mp_cmp(G->x, GG->x) != LTC_MP_EQ || mp_cmp(G->y, GG->y) != LTC_MP_EQ) {
          err = CRYPT_FAIL_TESTVECTOR;
          goto done;
       }
   }
   err = CRYPT_OK;
done:
   ltc_ecc_del_point(GG);
   ltc_ecc_del_point(G);
   mp_clear_multi(order, modulus, NULL);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_test.c,v $ */
/* $Revision: 1.12 $ */
/* $Date: 2007/05/12 14:32:35 $ */
