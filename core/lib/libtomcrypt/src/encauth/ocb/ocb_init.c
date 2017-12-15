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
   @file ocb_init.c
   OCB implementation, initialize state, by Tom St Denis
*/
#include "tomcrypt.h"

#ifdef LTC_OCB_MODE

static const struct {
    int           len;
    unsigned char poly_div[MAXBLOCKSIZE], 
                  poly_mul[MAXBLOCKSIZE];
} polys[] = {
{
    8,
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B }
}, {
    16, 
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 }
}
};

/**
  Initialize an OCB context.
  @param ocb     [out] The destination of the OCB state
  @param cipher  The index of the desired cipher
  @param key     The secret key
  @param keylen  The length of the secret key (octets)
  @param nonce   The session nonce (length of the block size of the cipher)
  @return CRYPT_OK if successful
*/
int ocb_init(ocb_state *ocb, int cipher, 
             const unsigned char *key, unsigned long keylen, const unsigned char *nonce)
{
   int poly, x, y, m, err;

   LTC_ARGCHK(ocb   != NULL);
   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(nonce != NULL);

   /* valid cipher? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* determine which polys to use */
   ocb->block_len = cipher_descriptor[cipher].block_length;
   x = (int)(sizeof(polys)/sizeof(polys[0]));
   for (poly = 0; poly < x; poly++) {
       if (polys[poly].len == ocb->block_len) { 
          break;
       }
   }
   if (poly == x) {
      return CRYPT_INVALID_ARG; /* block_len not found in polys */
   }
   if (polys[poly].len != ocb->block_len) {
      return CRYPT_INVALID_ARG;
   }   

   /* schedule the key */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &ocb->key)) != CRYPT_OK) {
      return err;
   }
 
   /* find L = E[0] */
   zeromem(ocb->L, ocb->block_len);
   if ((err = cipher_descriptor[cipher].ecb_encrypt(ocb->L, ocb->L, &ocb->key)) != CRYPT_OK) {
      return err;
   }

   /* find R = E[N xor L] */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->R[x] = ocb->L[x] ^ nonce[x];
   }
   if ((err = cipher_descriptor[cipher].ecb_encrypt(ocb->R, ocb->R, &ocb->key)) != CRYPT_OK) {
      return err;
   }

   /* find Ls[i] = L << i for i == 0..31 */
   XMEMCPY(ocb->Ls[0], ocb->L, ocb->block_len);
   for (x = 1; x < 32; x++) {
       m = ocb->Ls[x-1][0] >> 7;
       for (y = 0; y < ocb->block_len-1; y++) {
           ocb->Ls[x][y] = ((ocb->Ls[x-1][y] << 1) | (ocb->Ls[x-1][y+1] >> 7)) & 255;
       }
       ocb->Ls[x][ocb->block_len-1] = (ocb->Ls[x-1][ocb->block_len-1] << 1) & 255;

       if (m == 1) {
          for (y = 0; y < ocb->block_len; y++) {
              ocb->Ls[x][y] ^= polys[poly].poly_mul[y];
          }
       }
    }

    /* find Lr = L / x */
    m = ocb->L[ocb->block_len-1] & 1;

    /* shift right */
    for (x = ocb->block_len - 1; x > 0; x--) {
        ocb->Lr[x] = ((ocb->L[x] >> 1) | (ocb->L[x-1] << 7)) & 255;
    }
    ocb->Lr[0] = ocb->L[0] >> 1;

    if (m == 1) {
       for (x = 0; x < ocb->block_len; x++) {
           ocb->Lr[x] ^= polys[poly].poly_div[x];
       }
    }

    /* set Li, checksum */
    zeromem(ocb->Li,       ocb->block_len);
    zeromem(ocb->checksum, ocb->block_len);

    /* set other params */
    ocb->block_index = 1;
    ocb->cipher      = cipher;

    return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/encauth/ocb/ocb_init.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2007/05/12 14:32:35 $ */
