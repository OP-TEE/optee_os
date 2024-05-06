/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* AES-NI implementation by Steffen Jaeckel */
/**
  @file aesni.c
  Implementation of AES via the AES-NI instruction on x86_64
*/

#include "tomcrypt_private.h"

#if defined(LTC_HAS_AES_NI)

const struct ltc_cipher_descriptor aesni_desc =
{
    "aes",
    6,
    16, 32, 16, 10,
    aesni_setup, aesni_ecb_encrypt, aesni_ecb_decrypt, aesni_test, aesni_done, aesni_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#define setup_mix(t, c) _mm_extract_epi32(_mm_aeskeygenassist_si128(t, 0), c)
#define temp_load(k) _mm_loadu_si128((__m128i*)(k))
#define temp_update(t, k) _mm_insert_epi32(t, k, 3)
#define temp_invert(k) _mm_aesimc_si128(*((__m128i*)(k)))


static const ulong32 rcon[] = {
    0x01UL, 0x02UL, 0x04UL, 0x08UL, 0x10UL, 0x20UL, 0x40UL, 0x80UL, 0x1BUL, 0x36UL
};

 /**
    Initialize the AES (Rijndael) block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int aesni_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   int i;
   __m128i temp;
   ulong32 *rk, *K;
   ulong32 *rrk;
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (keylen != 16 && keylen != 24 && keylen != 32) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if (num_rounds != 0 && num_rounds != (keylen / 4 + 6)) {
      return CRYPT_INVALID_ROUNDS;
   }

   skey->rijndael.Nr = keylen / 4 + 6;
   K = LTC_ALIGN_BUF(skey->rijndael.K, 16);
   skey->rijndael.eK = K;
   K += 60;
   skey->rijndael.dK = K;

   /* setup the forward key */
   i = 0;
   rk = skey->rijndael.eK;
   LOAD32L(rk[0], key);
   LOAD32L(rk[1], key + 4);
   LOAD32L(rk[2], key + 8);
   LOAD32L(rk[3], key + 12);
   if (keylen == 16) {
      temp = temp_load(key);
      for (;;) {
         rk[4] = rk[0] ^ setup_mix(temp, 3) ^ rcon[i];
         rk[5] = rk[1] ^ rk[4];
         rk[6] = rk[2] ^ rk[5];
         rk[7] = rk[3] ^ rk[6];
         if (++i == 10) {
            break;
         }
         temp = temp_update(temp, rk[7]);
         rk += 4;
      }
   } else if (keylen == 24) {
      LOAD32L(rk[4], key + 16);
      LOAD32L(rk[5], key + 20);
      temp = temp_load(key + 8);
      for (;;) {
         rk[6] = rk[0] ^ setup_mix(temp, 3) ^ rcon[i];
         rk[7] = rk[1] ^ rk[6];
         rk[8] = rk[2] ^ rk[7];
         rk[9] = rk[3] ^ rk[8];
         if (++i == 8) {
            break;
         }
         rk[10] = rk[4] ^ rk[9];
         rk[11] = rk[5] ^ rk[10];
         temp = temp_update(temp, rk[11]);
         rk += 6;
      }
   } else if (keylen == 32) {
      LOAD32L(rk[4], key + 16);
      LOAD32L(rk[5], key + 20);
      LOAD32L(rk[6], key + 24);
      LOAD32L(rk[7], key + 28);
      temp = temp_load(key + 16);
      for (;;) {
         rk[8] = rk[0] ^ setup_mix(temp, 3) ^ rcon[i];
         rk[9] = rk[1] ^ rk[8];
         rk[10] = rk[2] ^ rk[9];
         rk[11] = rk[3] ^ rk[10];
         if (++i == 7) {
            break;
         }
         temp = temp_update(temp, rk[11]);
         rk[12] = rk[4] ^ setup_mix(temp, 2);
         rk[13] = rk[5] ^ rk[12];
         rk[14] = rk[6] ^ rk[13];
         rk[15] = rk[7] ^ rk[14];
         temp = temp_update(temp, rk[15]);
         rk += 8;
      }
   } else {
      /* this can't happen */
      /* coverity[dead_error_line] */
      return CRYPT_ERROR;
   }

   /* setup the inverse key now */
   rk = skey->rijndael.dK;
   rrk = skey->rijndael.eK + skey->rijndael.Nr * 4;

   /* apply the inverse MixColumn transform to all round keys but the first and the last: */
   /* copy first */
   *rk++ = *rrk++;
   *rk++ = *rrk++;
   *rk++ = *rrk++;
   *rk = *rrk;
   rk -= 3;
   rrk -= 3;

   for (i = 1; i < skey->rijndael.Nr; i++) {
      rrk -= 4;
      rk += 4;
      temp = temp_invert(rk);
      *((__m128i*) rk) = temp_invert(rrk);
   }

   /* copy last */
   rrk -= 4;
   rk += 4;
   *rk++ = *rrk++;
   *rk++ = *rrk++;
   *rk++ = *rrk++;
   *rk = *rrk;

   return CRYPT_OK;
}

/**
  Encrypts a block of text with AES
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
#ifdef LTC_CLEAN_STACK
static int s_aesni_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
#else
int aesni_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
#endif
{
   int Nr, r;
   const __m128i *skeys;
   __m128i block;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);

   Nr = skey->rijndael.Nr;

   if (Nr < 2 || Nr > 16) return CRYPT_INVALID_ROUNDS;

   skeys = (__m128i*) skey->rijndael.eK;
   block = _mm_loadu_si128((const __m128i*) (pt));

   block = _mm_xor_si128(block, skeys[0]);
   for (r = 1; r < Nr - 1; r += 2) {
      block = _mm_aesenc_si128(block, skeys[r]);
      block = _mm_aesenc_si128(block, skeys[r + 1]);
   }
   block = _mm_aesenc_si128(block, skeys[Nr - 1]);
   block = _mm_aesenclast_si128(block, skeys[Nr]);

   _mm_storeu_si128((__m128i*) ct, block);

   return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
int aesni_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
   int err = s_aesni_ecb_encrypt(pt, ct, skey);
   burn_stack(sizeof(unsigned long)*8 + sizeof(unsigned long*) + sizeof(int)*2);
   return err;
}
#endif


/**
  Decrypts a block of text with AES
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
#ifdef LTC_CLEAN_STACK
static int s_aesni_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
#else
int aesni_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
#endif
{
   int Nr, r;
   const __m128i *skeys;
   __m128i block;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);

   Nr = skey->rijndael.Nr;

   if (Nr < 2 || Nr > 16) return CRYPT_INVALID_ROUNDS;

   skeys = (__m128i*) skey->rijndael.dK;
   block = _mm_loadu_si128((const __m128i*) (ct));

   block = _mm_xor_si128(block, skeys[0]);
   for (r = 1; r < Nr - 1; r += 2) {
      block = _mm_aesdec_si128(block, skeys[r]);
      block = _mm_aesdec_si128(block, skeys[r + 1]);
   }
   block = _mm_aesdec_si128(block, skeys[Nr - 1]);
   block = _mm_aesdeclast_si128(block, skeys[Nr]);

   _mm_storeu_si128((__m128i*) pt, block);

   return CRYPT_OK;
}


#ifdef LTC_CLEAN_STACK
int aesni_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
   int err = s_aesni_ecb_decrypt(ct, pt, skey);
   burn_stack(sizeof(unsigned long)*8 + sizeof(unsigned long*) + sizeof(int)*2);
   return err;
}
#endif

/**
  Performs a self-test of the AES block cipher
  @return CRYPT_OK if functional, CRYPT_NOP if self-test has been disabled
*/
int aesni_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
 int err;
 static const struct {
     int keylen;
     unsigned char key[32], pt[16], ct[16];
 } tests[] = {
    { 16,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }
    }, {
      24,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }
    }, {
      32,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }
    }
 };

  symmetric_key key;
  unsigned char tmp[2][16];
  int i, y;

  for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
    zeromem(&key, sizeof(key));
    if ((err = aesni_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
       return err;
    }

    aesni_ecb_encrypt(tests[i].pt, tmp[0], &key);
    aesni_ecb_decrypt(tmp[0], tmp[1], &key);
    if (compare_testvector(tmp[0], 16, tests[i].ct, 16, "AES-NI Encrypt", i) ||
          compare_testvector(tmp[1], 16, tests[i].pt, 16, "AES-NI Decrypt", i)) {
        return CRYPT_FAIL_TESTVECTOR;
    }

    /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
    for (y = 0; y < 16; y++) tmp[0][y] = 0;
    for (y = 0; y < 1000; y++) aesni_ecb_encrypt(tmp[0], tmp[0], &key);
    for (y = 0; y < 1000; y++) aesni_ecb_decrypt(tmp[0], tmp[0], &key);
    for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;
  }
  return CRYPT_OK;
 #endif
}


/** Terminate the context
   @param skey    The scheduled key
*/
void aesni_done(symmetric_key *skey)
{
  LTC_UNUSED_PARAM(skey);
}


/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in bytes).  This function will store the suitable size back in this variable.
  @return CRYPT_OK if the input key size is acceptable.
*/
int aesni_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize < 16) {
      return CRYPT_INVALID_KEYSIZE;
   }
   if (*keysize < 24) {
      *keysize = 16;
      return CRYPT_OK;
   }
   if (*keysize < 32) {
      *keysize = 24;
      return CRYPT_OK;
   }
   *keysize = 32;
   return CRYPT_OK;
}

#endif

