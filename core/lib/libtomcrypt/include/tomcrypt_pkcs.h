/* SPDX-License-Identifier: BSD-2-Clause */
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

/* LTC_PKCS Header Info */

/* ===> LTC_PKCS #1 -- RSA Cryptography <=== */
#ifdef LTC_PKCS_1

enum ltc_pkcs_1_v1_5_blocks
{
  LTC_PKCS_1_EMSA   = 1,        /* Block type 1 (PKCS #1 v1.5 signature padding) */
  LTC_PKCS_1_EME    = 2         /* Block type 2 (PKCS #1 v1.5 encryption padding) */
};

enum ltc_pkcs_1_paddings
{
  LTC_PKCS_1_V1_5      = 1,        /* PKCS #1 v1.5 padding (\sa ltc_pkcs_1_v1_5_blocks) */
  LTC_PKCS_1_OAEP      = 2,        /* PKCS #1 v2.0 encryption padding */
  LTC_PKCS_1_PSS       = 3,        /* PKCS #1 v2.1 signature padding */
  LTC_PKCS_1_V1_5_NA1  = 4,        /* PKSC #1 v1.5 no ASN.1 */
};

int pkcs_1_mgf1(      int            hash_idx,
                const unsigned char *seed, unsigned long seedlen,
                      unsigned char *mask, unsigned long masklen);

int pkcs_1_i2osp(void *n, unsigned long modulus_len, unsigned char *out);
int pkcs_1_os2ip(void *n, unsigned char *in, unsigned long inlen);

/* *** v1.5 padding */
int pkcs_1_v1_5_encode(const unsigned char *msg, 
                             unsigned long  msglen,
                             int            block_type,
                             unsigned long  modulus_bitlen,
                                prng_state *prng, 
                                       int  prng_idx,
                             unsigned char *out, 
                             unsigned long *outlen);

int pkcs_1_v1_5_decode(const unsigned char *msg, 
                             unsigned long  msglen,
                                       int  block_type,
                             unsigned long  modulus_bitlen,
                             unsigned char *out, 
                             unsigned long *outlen,
                                       int *is_valid);

/* *** v2.1 padding */
int pkcs_1_oaep_encode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, prng_state *prng,
                             int           prng_idx,         int  hash_idx,
                             unsigned char *out,    unsigned long *outlen);

int pkcs_1_oaep_decode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, int hash_idx,
                             unsigned char *out,    unsigned long *outlen,
                             int           *res);

int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
                            unsigned long saltlen,  prng_state   *prng,     
                            int           prng_idx, int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen);

int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res);

#endif /* LTC_PKCS_1 */

/* ===> LTC_PKCS #5 -- Password Based Cryptography <=== */
#ifdef LTC_PKCS_5

/* Algorithm #1 (old) */
int pkcs_5_alg1(const unsigned char *password, unsigned long password_len, 
                const unsigned char *salt, 
                int iteration_count,  int hash_idx,
                unsigned char *out,   unsigned long *outlen);

/* Algorithm #2 (new) */
int pkcs_5_alg2(const unsigned char *password, unsigned long password_len, 
                const unsigned char *salt,     unsigned long salt_len,
                int iteration_count,           int hash_idx,
                unsigned char *out,            unsigned long *outlen);

#endif  /* LTC_PKCS_5 */

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_pkcs.h,v $ */
/* $Revision: 1.8 $ */
/* $Date: 2007/05/12 14:32:35 $ */
