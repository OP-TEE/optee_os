/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Auto-detection of AES implementation by Steffen Jaeckel */
/**
  @file aes_desc.c
  Run-time detection of correct AES implementation
*/

#include "tomcrypt_private.h"

#if defined(LTC_RIJNDAEL)

#ifndef ENCRYPT_ONLY

#define AES_SETUP aes_setup
#define AES_ENC   aes_ecb_encrypt
#define AES_DEC   aes_ecb_decrypt
#define AES_DONE  aes_done
#define AES_TEST  aes_test
#define AES_KS    aes_keysize

const struct ltc_cipher_descriptor aes_desc =
{
    "aes",
    6,
    16, 32, 16, 10,
    AES_SETUP, AES_ENC, AES_DEC, AES_TEST, AES_DONE, AES_KS,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#else

#define AES_SETUP aes_enc_setup
#define AES_ENC   aes_enc_ecb_encrypt
#define AES_DONE  aes_enc_done
#define AES_TEST  aes_enc_test
#define AES_KS    aes_enc_keysize

const struct ltc_cipher_descriptor aes_enc_desc =
{
    "aes",
    6,
    16, 32, 16, 10,
    AES_SETUP, AES_ENC, NULL, NULL, AES_DONE, AES_KS,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif

/* Code partially borrowed from https://software.intel.com/content/www/us/en/develop/articles/intel-sha-extensions.html */
#if defined(LTC_HAS_AES_NI)
static LTC_INLINE int s_aesni_is_supported(void)
{
   static int initialized = 0, is_supported = 0;

   if (initialized == 0) {
      int a, b, c, d;

      /* Look for CPUID.1.0.ECX[25]
       * EAX = 1, ECX = 0
       */
      a = 1;
      c = 0;

      asm volatile ("cpuid"
           :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
           :"a"(a), "c"(c)
          );

      is_supported = ((c >> 25) & 1);
      initialized = 1;
   }

   return is_supported;
}

#ifndef ENCRYPT_ONLY
int aesni_is_supported(void)
{
   return s_aesni_is_supported();
}
#endif
#endif

 /**
    Initialize the AES (Rijndael) block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int AES_SETUP(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
#ifdef LTC_HAS_AES_NI
   if (s_aesni_is_supported()) {
      return aesni_setup(key, keylen, num_rounds, skey);
   }
#endif
   /* Last resort, software AES */
   return rijndael_setup(key, keylen, num_rounds, skey);
}

/**
  Encrypts a block of text with AES
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int AES_ENC(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
#ifdef LTC_HAS_AES_NI
   if (s_aesni_is_supported()) {
      return aesni_ecb_encrypt(pt, ct, skey);
   }
#endif
   return rijndael_ecb_encrypt(pt, ct, skey);
}


#ifndef ENCRYPT_ONLY
/**
  Decrypts a block of text with AES
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int AES_DEC(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
#ifdef LTC_HAS_AES_NI
   if (s_aesni_is_supported()) {
      return aesni_ecb_decrypt(ct, pt, skey);
   }
#endif
   return rijndael_ecb_decrypt(ct, pt, skey);
}
#endif /* ENCRYPT_ONLY */

/**
  Performs a self-test of the AES block cipher
  @return CRYPT_OK if functional, CRYPT_NOP if self-test has been disabled
*/
int AES_TEST(void)
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
  int i;
#ifndef ENCRYPT_ONLY
  int y;
#endif

  for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
    zeromem(&key, sizeof(key));
    if ((err = AES_SETUP(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
       return err;
    }

    AES_ENC(tests[i].pt, tmp[0], &key);
    if (compare_testvector(tmp[0], 16, tests[i].ct, 16, "AES Encrypt", i)) {
        return CRYPT_FAIL_TESTVECTOR;
    }
#ifndef ENCRYPT_ONLY
    AES_DEC(tmp[0], tmp[1], &key);
    if (compare_testvector(tmp[1], 16, tests[i].pt, 16, "AES Decrypt", i)) {
        return CRYPT_FAIL_TESTVECTOR;
    }

    /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
    for (y = 0; y < 16; y++) tmp[0][y] = 0;
    for (y = 0; y < 1000; y++) AES_ENC(tmp[0], tmp[0], &key);
    for (y = 0; y < 1000; y++) AES_DEC(tmp[0], tmp[0], &key);
    for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;
#endif
  }
  return CRYPT_OK;
 #endif
}


/** Terminate the context
   @param skey    The scheduled key
*/
void AES_DONE(symmetric_key *skey)
{
  LTC_UNUSED_PARAM(skey);
}


/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in bytes).  This function will store the suitable size back in this variable.
  @return CRYPT_OK if the input key size is acceptable.
*/
int AES_KS(int *keysize)
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

