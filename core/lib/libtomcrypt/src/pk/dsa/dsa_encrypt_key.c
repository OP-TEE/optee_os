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
  @file dsa_encrypt_key.c
  DSA Crypto, Tom St Denis
*/  

#ifdef LTC_MDSA

/**
  Encrypt a symmetric key with DSA
  @param in         The symmetric key you want to encrypt
  @param inlen      The length of the key to encrypt (octets)
  @param out        [out] The destination for the ciphertext
  @param outlen     [in/out] The max size and resulting size of the ciphertext
  @param prng       An active PRNG state
  @param wprng      The index of the PRNG you wish to use 
  @param hash       The index of the hash you want to use 
  @param key        The DSA key you want to encrypt to
  @return CRYPT_OK if successful
*/
int dsa_encrypt_key(const unsigned char *in,   unsigned long inlen,
                          unsigned char *out,  unsigned long *outlen, 
                          prng_state *prng, int wprng, int hash, 
                          dsa_key *key)
{
    unsigned char *expt, *skey;
    void          *g_pub, *g_priv;
    unsigned long  x, y;
    int            err, qbits;

    LTC_ARGCHK(in      != NULL);
    LTC_ARGCHK(out     != NULL);
    LTC_ARGCHK(outlen  != NULL);
    LTC_ARGCHK(key     != NULL);

    /* check that wprng/cipher/hash are not invalid */
    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
       return err;
    }

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (inlen > hash_descriptor[hash]->hashsize) {
       return CRYPT_INVALID_HASH;
    }

    /* make a random key and export the public copy */
    if ((err = mp_init_multi(&g_pub, &g_priv, NULL)) != CRYPT_OK) {
       return err;
    }
   
    expt       = XMALLOC(mp_unsigned_bin_size(key->p) + 1);
    skey       = XMALLOC(MAXBLOCKSIZE);
    if (expt == NULL  || skey == NULL) {
       if (expt != NULL) {
          XFREE(expt);
       }
       if (skey != NULL) {
          XFREE(skey);
       }
       mp_clear_multi(g_pub, g_priv, NULL);
       return CRYPT_MEM;
    }
    
    /* make a random g_priv, g_pub = g^x pair */
    qbits = mp_count_bits(key->q);
    do {
      if ((err = rand_bn_bits(g_priv, qbits, prng, wprng)) != CRYPT_OK) {
        goto LBL_ERR;
      }
      /* private key x should be from range: 1 <= x <= q-1 (see FIPS 186-4 B.1.2) */
    } while (mp_cmp_d(g_priv, 0) != LTC_MP_GT || mp_cmp(g_priv, key->q) != LTC_MP_LT);

    /* compute y */
    if ((err = mp_exptmod(key->g, g_priv, key->p, g_pub)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    
    /* make random key */
    x        = mp_unsigned_bin_size(key->p) + 1;
    if ((err = dsa_shared_secret(g_priv, key->y, key, expt, &x)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    y = MAXBLOCKSIZE;
    if ((err = hash_memory(hash, expt, x, skey, &y)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    
    /* Encrypt key */
    for (x = 0; x < inlen; x++) {
      skey[x] ^= in[x];
    }

    err = der_encode_sequence_multi(out, outlen,
                                    LTC_ASN1_OBJECT_IDENTIFIER,  hash_descriptor[hash]->OIDlen,   hash_descriptor[hash]->OID,
                                    LTC_ASN1_INTEGER,            1UL,                            g_pub,
                                    LTC_ASN1_OCTET_STRING,       inlen,                          skey,
                                    LTC_ASN1_EOL,                0UL,                            NULL);

LBL_ERR:
#ifdef LTC_CLEAN_STACK
    /* clean up */
    zeromem(expt,   mp_unsigned_bin_size(key->p) + 1);
    zeromem(skey,   MAXBLOCKSIZE);
#endif

    XFREE(skey);
    XFREE(expt);
    
    mp_clear_multi(g_pub, g_priv, NULL);
    return err;
}

#endif
/* $Source: /cvs/libtom/libtomcrypt/src/pk/dsa/dsa_encrypt_key.c,v $ */
/* $Revision: 1.9 $ */
/* $Date: 2007/05/12 14:32:35 $ */
