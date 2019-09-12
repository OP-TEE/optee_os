// SPDX-License-Identifier: BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file ccm_test.c
  CCM support, process a block of memory, Tom St Denis
*/

#ifdef LTC_CCM_MODE

int ccm_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
       unsigned char key[16];
       unsigned char nonce[16];
       int           noncelen;
       unsigned char header[64];
       int           headerlen;
       unsigned char pt[64];
       int           ptlen;
       unsigned char ct[64];
       unsigned char tag[16];
       unsigned long taglen;
   } tests[] = {

/* 13 byte nonce, 8 byte auth, 23 byte pt */
{
   { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
     0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF },
   { 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0,
     0xA1, 0xA2, 0xA3, 0xA4, 0xA5 },
   13,
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
   8,
   { 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E },
   23,
   { 0x58, 0x8C, 0x97, 0x9A, 0x61, 0xC6, 0x63, 0xD2,
     0xF0, 0x66, 0xD0, 0xC2, 0xC0, 0xF9, 0x89, 0x80,
     0x6D, 0x5F, 0x6B, 0x61, 0xDA, 0xC3, 0x84 },
   { 0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0 },
   8
},

/* 13 byte nonce, 12 byte header, 19 byte pt */
{
   { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
     0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF },
   { 0x00, 0x00, 0x00, 0x06, 0x05, 0x04, 0x03, 0xA0,
     0xA1, 0xA2, 0xA3, 0xA4, 0xA5 },
   13,
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B },
   12,
   { 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
     0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
     0x1C, 0x1D, 0x1E },
   19,
   { 0xA2, 0x8C, 0x68, 0x65, 0x93, 0x9A, 0x9A, 0x79,
     0xFA, 0xAA, 0x5C, 0x4C, 0x2A, 0x9D, 0x4A, 0x91,
     0xCD, 0xAC, 0x8C },
   { 0x96, 0xC8, 0x61, 0xB9, 0xC9, 0xE6, 0x1E, 0xF1 },
   8
},

/* supplied by Brian Gladman */
{
   { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f },
   { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16  },
   7,
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
   8,
   { 0x20, 0x21, 0x22, 0x23 },
   4,
   { 0x71, 0x62, 0x01, 0x5b },
   { 0x4d, 0xac, 0x25, 0x5d },
   4
},

{
   { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
     0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f },
   { 0x00, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xb5,
     0x03, 0x97, 0x76, 0xe7, 0x0c },
   13,
   { 0x08, 0x40, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c,
     0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xab, 0xae,
     0xa5, 0xb8, 0xfc, 0xba, 0x00, 0x00 },
   22,
   { 0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
     0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
     0x7e, 0x78, 0xa0, 0x50 },
   20,
   { 0xf3, 0xd0, 0xa2, 0xfe, 0x9a, 0x3d, 0xbf, 0x23,
     0x42, 0xa6, 0x43, 0xe4, 0x32, 0x46, 0xe8, 0x0c,
     0x3c, 0x04, 0xd0, 0x19 },
   { 0x78, 0x45, 0xce, 0x0b, 0x16, 0xf9, 0x76, 0x23 },
   8
},

};
   unsigned long taglen, x, y;
   unsigned char buf[64], buf2[64], tag[16], tag2[16], tag3[16], zero[64];
   int           err, idx;
   symmetric_key skey;
   ccm_state ccm;

   zeromem(zero, 64);

   idx = find_cipher("aes");
   if (idx == -1) {
      idx = find_cipher("rijndael");
      if (idx == -1) {
         return CRYPT_NOP;
      }
   }

   for (x = 0; x < (sizeof(tests)/sizeof(tests[0])); x++) {
      for (y = 0; y < 2; y++) {
         taglen = tests[x].taglen;
         if (y == 0) {
            if ((err = cipher_descriptor[idx]->setup(tests[x].key, 16, 0, &skey)) != CRYPT_OK) {
               return err;
            }

            if ((err = ccm_memory(idx,
                                  tests[x].key, 16,
                                  &skey,
                                  tests[x].nonce, tests[x].noncelen,
                                  tests[x].header, tests[x].headerlen,
                                  (unsigned char*)tests[x].pt, tests[x].ptlen,
                                  buf,
                                  tag, &taglen, 0)) != CRYPT_OK) {
               return err;
            }
            /* run a second time to make sure skey is not touched */
            if ((err = ccm_memory(idx,
                                  tests[x].key, 16,
                                  &skey,
                                  tests[x].nonce, tests[x].noncelen,
                                  tests[x].header, tests[x].headerlen,
                                  (unsigned char*)tests[x].pt, tests[x].ptlen,
                                  buf,
                                  tag, &taglen, 0)) != CRYPT_OK) {
               return err;
            }
         } else {
            if ((err = ccm_init(&ccm, idx, tests[x].key, 16, tests[x].ptlen, tests[x].taglen, tests[x].headerlen)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_add_nonce(&ccm, tests[x].nonce, tests[x].noncelen)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_add_aad(&ccm, tests[x].header, tests[x].headerlen)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_process(&ccm, (unsigned char*)tests[x].pt, tests[x].ptlen, buf, CCM_ENCRYPT)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_done(&ccm, tag, &taglen)) != CRYPT_OK) {
               return err;
            }
         }

         if (compare_testvector(buf, tests[x].ptlen, tests[x].ct, tests[x].ptlen, "CCM encrypt data", x)) {
            return CRYPT_FAIL_TESTVECTOR;
         }
         if (compare_testvector(tag, taglen, tests[x].tag, tests[x].taglen, "CCM encrypt tag", x)) {
            return CRYPT_FAIL_TESTVECTOR;
         }

         if (y == 0) {
            XMEMCPY(tag3, tests[x].tag, tests[x].taglen);
            taglen = tests[x].taglen;
            if ((err = ccm_memory(idx,
                                  tests[x].key, 16,
                                  NULL,
                                  tests[x].nonce, tests[x].noncelen,
                                  tests[x].header, tests[x].headerlen,
                                  buf2, tests[x].ptlen,
                                  buf,
                                  tag3, &taglen, 1   )) != CRYPT_OK) {
               return err;
            }
         } else {
            if ((err = ccm_init(&ccm, idx, tests[x].key, 16, tests[x].ptlen, tests[x].taglen, tests[x].headerlen)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_add_nonce(&ccm, tests[x].nonce, tests[x].noncelen)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_add_aad(&ccm, tests[x].header, tests[x].headerlen)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_process(&ccm, buf2, tests[x].ptlen, buf, CCM_DECRYPT)) != CRYPT_OK) {
               return err;
            }
            if ((err = ccm_done(&ccm, tag2, &taglen)) != CRYPT_OK) {
               return err;
            }
         }


         if (compare_testvector(buf2, tests[x].ptlen, tests[x].pt, tests[x].ptlen, "CCM decrypt data", x)) {
            return CRYPT_FAIL_TESTVECTOR;
         }
         if (y == 0) {
            /* check if decryption with the wrong tag does not reveal the plaintext */
            XMEMCPY(tag3, tests[x].tag, tests[x].taglen);
            tag3[0] ^= 0xff; /* set the tag to the wrong value */
            taglen = tests[x].taglen;
            if ((err = ccm_memory(idx,
                                  tests[x].key, 16,
                                  NULL,
                                  tests[x].nonce, tests[x].noncelen,
                                  tests[x].header, tests[x].headerlen,
                                  buf2, tests[x].ptlen,
                                  buf,
                                  tag3, &taglen, 1   )) != CRYPT_ERROR) {
               return CRYPT_FAIL_TESTVECTOR;
            }
            if (compare_testvector(buf2, tests[x].ptlen, zero, tests[x].ptlen, "CCM decrypt wrong tag", x)) {
               return CRYPT_FAIL_TESTVECTOR;
            }
         } else {
            if (compare_testvector(tag2, taglen, tests[x].tag, tests[x].taglen, "CCM decrypt tag", x)) {
               return CRYPT_FAIL_TESTVECTOR;
            }
         }

         if (y == 0) {
            cipher_descriptor[idx]->done(&skey);
         }
      }
   }

   /* wycheproof failing test - https://github.com/libtom/libtomcrypt/pull/452 */
   {
      unsigned char key[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
      unsigned char iv[]  = { 0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51 };
      unsigned char valid_tag[]   = { 0x23,0x1a,0x2d,0x8f };
      unsigned char invalid_tag[] = { 0x23,0x1a,0x2d,0x8f,0x6a };
      unsigned char msg[] = { 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f };
      unsigned char ct[]  = { 0xd3,0xda,0xb1,0xee,0x49,0x4c,0xc2,0x29,0x09,0x9d,0x6c,0xac,0x7d,0xf1,0x4a,0xdd };
      unsigned char pt[20] = { 0 };

      /* VALID tag */
      taglen = sizeof(valid_tag);
      err = ccm_memory(idx, key, sizeof(key), NULL, iv, sizeof(iv), NULL, 0,
                       pt, sizeof(ct), ct, valid_tag, &taglen, CCM_DECRYPT);
      if ((err != CRYPT_OK) || (XMEMCMP(msg, pt, sizeof(msg)) != 0)) {
         return CRYPT_FAIL_TESTVECTOR;
      }

      /* INVALID tag */
      taglen = sizeof(invalid_tag);
      err = ccm_memory(idx, key, sizeof(key), NULL, iv, sizeof(iv), NULL, 0,
                       pt, sizeof(ct), ct, invalid_tag, &taglen, CCM_DECRYPT);
      if (err == CRYPT_OK) {
         return CRYPT_FAIL_TESTVECTOR; /* should fail */
      }
   }

   return CRYPT_OK;
#endif
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
