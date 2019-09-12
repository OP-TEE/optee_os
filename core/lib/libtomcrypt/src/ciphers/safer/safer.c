// SPDX-License-Identifier: BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/*******************************************************************************
*
* FILE:           safer.c
*
* LTC_DESCRIPTION:    block-cipher algorithm LTC_SAFER (Secure And Fast Encryption
*                 Routine) in its four versions: LTC_SAFER K-64, LTC_SAFER K-128,
*                 LTC_SAFER SK-64 and LTC_SAFER SK-128.
*
* AUTHOR:         Richard De Moliner (demoliner@isi.ee.ethz.ch)
*                 Signal and Information Processing Laboratory
*                 Swiss Federal Institute of Technology
*                 CH-8092 Zuerich, Switzerland
*
* DATE:           September 9, 1995
*
* CHANGE HISTORY:
*
*******************************************************************************/

#include "tomcrypt_private.h"

#ifdef LTC_SAFER

#define __LTC_SAFER_TAB_C__
#include "safer_tab.c"

const struct ltc_cipher_descriptor safer_k64_desc = {
   "safer-k64",
   8, 8, 8, 8, LTC_SAFER_K64_DEFAULT_NOF_ROUNDS,
   &safer_k64_setup,
   &safer_ecb_encrypt,
   &safer_ecb_decrypt,
   &safer_k64_test,
   &safer_done,
   &safer_64_keysize,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
   },

   safer_sk64_desc = {
   "safer-sk64",
   9, 8, 8, 8, LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS,
   &safer_sk64_setup,
   &safer_ecb_encrypt,
   &safer_ecb_decrypt,
   &safer_sk64_test,
   &safer_done,
   &safer_64_keysize,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
   },

   safer_k128_desc = {
   "safer-k128",
   10, 16, 16, 8, LTC_SAFER_K128_DEFAULT_NOF_ROUNDS,
   &safer_k128_setup,
   &safer_ecb_encrypt,
   &safer_ecb_decrypt,
   &safer_sk128_test,
   &safer_done,
   &safer_128_keysize,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
   },

   safer_sk128_desc = {
   "safer-sk128",
   11, 16, 16, 8, LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS,
   &safer_sk128_setup,
   &safer_ecb_encrypt,
   &safer_ecb_decrypt,
   &safer_sk128_test,
   &safer_done,
   &safer_128_keysize,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
   };

/******************* Constants ************************************************/
/* #define TAB_LEN      256  */

/******************* Assertions ***********************************************/

/******************* Macros ***************************************************/
#define ROL8(x, n)   ((unsigned char)((unsigned int)(x) << (n)\
                                     |(unsigned int)((x) & 0xFF) >> (8 - (n))))
#define EXP(x)       safer_ebox[(x) & 0xFF]
#define LOG(x)       safer_lbox[(x) & 0xFF]
#define PHT(x, y)    { y += x; x += y; }
#define IPHT(x, y)   { x -= y; y -= x; }

/******************* Types ****************************************************/

#ifdef LTC_CLEAN_STACK
static void _Safer_Expand_Userkey(const unsigned char *userkey_1,
                                 const unsigned char *userkey_2,
                                 unsigned int nof_rounds,
                                 int strengthened,
                                 safer_key_t key)
#else
static void Safer_Expand_Userkey(const unsigned char *userkey_1,
                                 const unsigned char *userkey_2,
                                 unsigned int nof_rounds,
                                 int strengthened,
                                 safer_key_t key)
#endif
{   unsigned int i, j, k;
    unsigned char ka[LTC_SAFER_BLOCK_LEN + 1];
    unsigned char kb[LTC_SAFER_BLOCK_LEN + 1];

    if (LTC_SAFER_MAX_NOF_ROUNDS < nof_rounds) {
        nof_rounds = LTC_SAFER_MAX_NOF_ROUNDS;
    }
    *key++ = (unsigned char)nof_rounds;
    ka[LTC_SAFER_BLOCK_LEN] = (unsigned char)0;
    kb[LTC_SAFER_BLOCK_LEN] = (unsigned char)0;
    k = 0;
    for (j = 0; j < LTC_SAFER_BLOCK_LEN; j++) {
        ka[j] = ROL8(userkey_1[j], 5);
        ka[LTC_SAFER_BLOCK_LEN] ^= ka[j];
        kb[j] = *key++ = userkey_2[j];
        kb[LTC_SAFER_BLOCK_LEN] ^= kb[j];
    }
    for (i = 1; i <= nof_rounds; i++) {
        for (j = 0; j < LTC_SAFER_BLOCK_LEN + 1; j++) {
            ka[j] = ROL8(ka[j], 6);
            kb[j] = ROL8(kb[j], 6);
        }
        if (strengthened) {
           k = 2 * i - 1;
           while (k >= (LTC_SAFER_BLOCK_LEN + 1)) { k -= LTC_SAFER_BLOCK_LEN + 1; }
        }
        for (j = 0; j < LTC_SAFER_BLOCK_LEN; j++) {
            if (strengthened) {
                *key++ = (ka[k]
                                + safer_ebox[(int)safer_ebox[(int)((18 * i + j + 1)&0xFF)]]) & 0xFF;
                if (++k == (LTC_SAFER_BLOCK_LEN + 1)) { k = 0; }
            } else {
                *key++ = (ka[j] + safer_ebox[(int)safer_ebox[(int)((18 * i + j + 1)&0xFF)]]) & 0xFF;
            }
        }
        if (strengthened) {
           k = 2 * i;
           while (k >= (LTC_SAFER_BLOCK_LEN + 1)) { k -= LTC_SAFER_BLOCK_LEN + 1; }
        }
        for (j = 0; j < LTC_SAFER_BLOCK_LEN; j++) {
            if (strengthened) {
                *key++ = (kb[k]
                                + safer_ebox[(int)safer_ebox[(int)((18 * i + j + 10)&0xFF)]]) & 0xFF;
                if (++k == (LTC_SAFER_BLOCK_LEN + 1)) { k = 0; }
            } else {
                *key++ = (kb[j] + safer_ebox[(int)safer_ebox[(int)((18 * i + j + 10)&0xFF)]]) & 0xFF;
            }
        }
    }

#ifdef LTC_CLEAN_STACK
    zeromem(ka, sizeof(ka));
    zeromem(kb, sizeof(kb));
#endif
}

#ifdef LTC_CLEAN_STACK
static void Safer_Expand_Userkey(const unsigned char *userkey_1,
                                 const unsigned char *userkey_2,
                                 unsigned int nof_rounds,
                                 int strengthened,
                                 safer_key_t key)
{
   _Safer_Expand_Userkey(userkey_1, userkey_2, nof_rounds, strengthened, key);
   burn_stack(sizeof(unsigned char) * (2 * (LTC_SAFER_BLOCK_LEN + 1)) + sizeof(unsigned int)*2);
}
#endif

int safer_k64_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && (num_rounds < 6 || num_rounds > LTC_SAFER_MAX_NOF_ROUNDS)) {
      return CRYPT_INVALID_ROUNDS;
   }

   if (keylen != 8) {
      return CRYPT_INVALID_KEYSIZE;
   }

   Safer_Expand_Userkey(key, key, (unsigned int)(num_rounds != 0 ?num_rounds:LTC_SAFER_K64_DEFAULT_NOF_ROUNDS), 0, skey->safer.key);
   return CRYPT_OK;
}

int safer_sk64_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && (num_rounds < 6 || num_rounds > LTC_SAFER_MAX_NOF_ROUNDS)) {
      return CRYPT_INVALID_ROUNDS;
   }

   if (keylen != 8) {
      return CRYPT_INVALID_KEYSIZE;
   }

   Safer_Expand_Userkey(key, key, (unsigned int)(num_rounds != 0 ?num_rounds:LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS), 1, skey->safer.key);
   return CRYPT_OK;
}

int safer_k128_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && (num_rounds < 6 || num_rounds > LTC_SAFER_MAX_NOF_ROUNDS)) {
      return CRYPT_INVALID_ROUNDS;
   }

   if (keylen != 16) {
      return CRYPT_INVALID_KEYSIZE;
   }

   Safer_Expand_Userkey(key, key+8, (unsigned int)(num_rounds != 0 ?num_rounds:LTC_SAFER_K128_DEFAULT_NOF_ROUNDS), 0, skey->safer.key);
   return CRYPT_OK;
}

int safer_sk128_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && (num_rounds < 6 || num_rounds > LTC_SAFER_MAX_NOF_ROUNDS)) {
      return CRYPT_INVALID_ROUNDS;
   }

   if (keylen != 16) {
      return CRYPT_INVALID_KEYSIZE;
   }

   Safer_Expand_Userkey(key, key+8, (unsigned int)(num_rounds != 0?num_rounds:LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS), 1, skey->safer.key);
   return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
static int _safer_ecb_encrypt(const unsigned char *pt,
                             unsigned char *ct,
                             const symmetric_key *skey)
#else
int safer_ecb_encrypt(const unsigned char *pt,
                             unsigned char *ct,
                             const symmetric_key *skey)
#endif
{   unsigned char a, b, c, d, e, f, g, h, t;
    unsigned int round;
    const unsigned char *key;

    LTC_ARGCHK(pt != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey != NULL);

    key = skey->safer.key;
    a = pt[0]; b = pt[1]; c = pt[2]; d = pt[3];
    e = pt[4]; f = pt[5]; g = pt[6]; h = pt[7];
    if (LTC_SAFER_MAX_NOF_ROUNDS < (round = *key)) round = LTC_SAFER_MAX_NOF_ROUNDS;
    while(round-- > 0)
    {
        a ^= *++key; b += *++key; c += *++key; d ^= *++key;
        e ^= *++key; f += *++key; g += *++key; h ^= *++key;
        a = EXP(a) + *++key; b = LOG(b) ^ *++key;
        c = LOG(c) ^ *++key; d = EXP(d) + *++key;
        e = EXP(e) + *++key; f = LOG(f) ^ *++key;
        g = LOG(g) ^ *++key; h = EXP(h) + *++key;
        PHT(a, b); PHT(c, d); PHT(e, f); PHT(g, h);
        PHT(a, c); PHT(e, g); PHT(b, d); PHT(f, h);
        PHT(a, e); PHT(b, f); PHT(c, g); PHT(d, h);
        t = b; b = e; e = c; c = t; t = d; d = f; f = g; g = t;
    }
    a ^= *++key; b += *++key; c += *++key; d ^= *++key;
    e ^= *++key; f += *++key; g += *++key; h ^= *++key;
    ct[0] = a & 0xFF; ct[1] = b & 0xFF;
    ct[2] = c & 0xFF; ct[3] = d & 0xFF;
    ct[4] = e & 0xFF; ct[5] = f & 0xFF;
    ct[6] = g & 0xFF; ct[7] = h & 0xFF;
    return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
int safer_ecb_encrypt(const unsigned char *pt,
                             unsigned char *ct,
                             const symmetric_key *skey)
{
    int err = _safer_ecb_encrypt(pt, ct, skey);
    burn_stack(sizeof(unsigned char) * 9 + sizeof(unsigned int) + sizeof(unsigned char *));
    return err;
}
#endif

#ifdef LTC_CLEAN_STACK
static int _safer_ecb_decrypt(const unsigned char *ct,
                             unsigned char *pt,
                             const symmetric_key *skey)
#else
int safer_ecb_decrypt(const unsigned char *ct,
                             unsigned char *pt,
                             const symmetric_key *skey)
#endif
{   unsigned char a, b, c, d, e, f, g, h, t;
    unsigned int round;
    const unsigned char *key;

    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(pt != NULL);
    LTC_ARGCHK(skey != NULL);

    key = skey->safer.key;
    a = ct[0]; b = ct[1]; c = ct[2]; d = ct[3];
    e = ct[4]; f = ct[5]; g = ct[6]; h = ct[7];
    if (LTC_SAFER_MAX_NOF_ROUNDS < (round = *key)) round = LTC_SAFER_MAX_NOF_ROUNDS;
    key += LTC_SAFER_BLOCK_LEN * (1 + 2 * round);
    h ^= *key; g -= *--key; f -= *--key; e ^= *--key;
    d ^= *--key; c -= *--key; b -= *--key; a ^= *--key;
    while (round--)
    {
        t = e; e = b; b = c; c = t; t = f; f = d; d = g; g = t;
        IPHT(a, e); IPHT(b, f); IPHT(c, g); IPHT(d, h);
        IPHT(a, c); IPHT(e, g); IPHT(b, d); IPHT(f, h);
        IPHT(a, b); IPHT(c, d); IPHT(e, f); IPHT(g, h);
        h -= *--key; g ^= *--key; f ^= *--key; e -= *--key;
        d -= *--key; c ^= *--key; b ^= *--key; a -= *--key;
        h = LOG(h) ^ *--key; g = EXP(g) - *--key;
        f = EXP(f) - *--key; e = LOG(e) ^ *--key;
        d = LOG(d) ^ *--key; c = EXP(c) - *--key;
        b = EXP(b) - *--key; a = LOG(a) ^ *--key;
    }
    pt[0] = a & 0xFF; pt[1] = b & 0xFF;
    pt[2] = c & 0xFF; pt[3] = d & 0xFF;
    pt[4] = e & 0xFF; pt[5] = f & 0xFF;
    pt[6] = g & 0xFF; pt[7] = h & 0xFF;
    return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
int safer_ecb_decrypt(const unsigned char *ct,
                             unsigned char *pt,
                             const symmetric_key *skey)
{
    int err = _safer_ecb_decrypt(ct, pt, skey);
    burn_stack(sizeof(unsigned char) * 9 + sizeof(unsigned int) + sizeof(unsigned char *));
    return err;
}
#endif

int safer_64_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);
   if (*keysize < 8) {
      return CRYPT_INVALID_KEYSIZE;
   }
   *keysize = 8;
   return CRYPT_OK;
}

int safer_128_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);
   if (*keysize < 16) {
      return CRYPT_INVALID_KEYSIZE;
   }
   *keysize = 16;
   return CRYPT_OK;
}

int safer_k64_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
   static const unsigned char k64_pt[]  = { 1, 2, 3, 4, 5, 6, 7, 8 },
                              k64_key[] = { 8, 7, 6, 5, 4, 3, 2, 1 },
                              k64_ct[]  = { 200, 242, 156, 221, 135, 120, 62, 217 };

   symmetric_key skey;
   unsigned char buf[2][8];
   int err;

   /* test K64 */
   if ((err = safer_k64_setup(k64_key, 8, 6, &skey)) != CRYPT_OK) {
      return err;
   }
   safer_ecb_encrypt(k64_pt, buf[0], &skey);
   safer_ecb_decrypt(buf[0], buf[1], &skey);

   if (compare_testvector(buf[0], 8, k64_ct, 8, "Safer K64 Encrypt", 0) != 0 ||
         compare_testvector(buf[1], 8, k64_pt, 8, "Safer K64 Decrypt", 0) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
 #endif
}


int safer_sk64_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
   static const unsigned char sk64_pt[]  = { 1, 2, 3, 4, 5, 6, 7, 8 },
                              sk64_key[] = { 1, 2, 3, 4, 5, 6, 7, 8 },
                              sk64_ct[]  = { 95, 206, 155, 162, 5, 132, 56, 199 };

   symmetric_key skey;
   unsigned char buf[2][8];
   int err, y;

   /* test SK64 */
   if ((err = safer_sk64_setup(sk64_key, 8, 6, &skey)) != CRYPT_OK) {
      return err;
   }

   safer_ecb_encrypt(sk64_pt, buf[0], &skey);
   safer_ecb_decrypt(buf[0], buf[1], &skey);

   if (compare_testvector(buf[0], 8, sk64_ct, 8, "Safer SK64 Encrypt", 0) != 0 ||
         compare_testvector(buf[1], 8, sk64_pt, 8, "Safer SK64 Decrypt", 0) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
   for (y = 0; y < 8; y++) buf[0][y] = 0;
   for (y = 0; y < 1000; y++) safer_ecb_encrypt(buf[0], buf[0], &skey);
   for (y = 0; y < 1000; y++) safer_ecb_decrypt(buf[0], buf[0], &skey);
   for (y = 0; y < 8; y++) if (buf[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;

   return CRYPT_OK;
  #endif
}

/** Terminate the context
   @param skey    The scheduled key
*/
void safer_done(symmetric_key *skey)
{
  LTC_UNUSED_PARAM(skey);
}

int safer_sk128_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
   static const unsigned char sk128_pt[]  = { 1, 2, 3, 4, 5, 6, 7, 8 },
                              sk128_key[] = { 1, 2, 3, 4, 5, 6, 7, 8,
                                              0, 0, 0, 0, 0, 0, 0, 0 },
                              sk128_ct[]  = { 255, 120, 17, 228, 179, 167, 46, 113 };

   symmetric_key skey;
   unsigned char buf[2][8];
   int err, y;

   /* test SK128 */
   if ((err = safer_sk128_setup(sk128_key, 16, 0, &skey)) != CRYPT_OK) {
      return err;
   }
   safer_ecb_encrypt(sk128_pt, buf[0], &skey);
   safer_ecb_decrypt(buf[0], buf[1], &skey);

   if (compare_testvector(buf[0], 8, sk128_ct, 8, "Safer SK128 Encrypt", 0) != 0 ||
         compare_testvector(buf[1], 8, sk128_pt, 8, "Safer SK128 Decrypt", 0) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
   for (y = 0; y < 8; y++) buf[0][y] = 0;
   for (y = 0; y < 1000; y++) safer_ecb_encrypt(buf[0], buf[0], &skey);
   for (y = 0; y < 1000; y++) safer_ecb_decrypt(buf[0], buf[0], &skey);
   for (y = 0; y < 8; y++) if (buf[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;

   return CRYPT_OK;
 #endif
}

#endif




/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
